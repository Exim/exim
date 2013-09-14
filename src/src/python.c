/**************************************************
 *     Exim - an Internet mail transport agent    *
 *************************************************/

/* Copyright (c) 2013 Todd Lyons */

/* This Python add-on can be distributed under the same terms
 * as Exim itself.  See the file NOTICE for conditions of use
 * and distribution. */

/* Since Python may define some pre-processor definitions which affect
 * the standard headers on some systems, you must include Python.h
 * before any standard headers are included. */
#include <Python.h>
#include "exim.h"

/* A couple of macros that handle specific chars when parsing
 * a path and filename */
#define IS_SLASH(blah) ((blah) == '/')
#define IS_DOT(blah)   ((blah) == '.')

/* Module scoped python object */
PyObject *pModule;

/* UTILITY
 * First we have some utility functions that are used internally */

/* Get a filename from a full path. */
static char *
filename (const char *full)
{
  const char *file = full;

  for (; *full; full++)
  {
    if (IS_SLASH(*full))
      file = full + 1;
  }
  return CS file;
}

/* Get filename minus extension.  Only pass a filename to this
 * function, not a full path. It does try to detect slashes though. */
static char *
modulename (const char *full)
{
  char *file;
  int count = 0, done = 0;

  file = strdup( CS full);
  for (; *full && !done; full++)
  {
    /* Check for slashes just in case */
    if (IS_SLASH(*full))
      file = (char *)full + 1;
    else if (IS_DOT(*full))
    {
      file[count] = '\0';
      done = 1;
    }
    count++;
  }
  return CS file;
}

/* Get the directory portion of a path+filename. */
static char *
basedir (const char *full)
{
  char *dir;
  int match = 0, count = 0;

  dir = strdup( CS full);
  for (; *full; full++)
  {
    if (IS_SLASH(*full))
      match = count;
    count++;
  }
  if (match > 0)
    dir[match] = '\0';
  return dir;
}

/* When an exception occurs, based on python_log_exceptions value,
 * generate a oneline description of the exception or the full
 * stack trace, and put in an error return pointer. */
static int *
handle_python_exception(uschar *name, uschar **errstrp)
{
  PyObject *pType, *pValue, *pTraceback;
  /* Catch the sys.exit() calls and log the exit value */
  if (PyErr_ExceptionMatches(PyExc_SystemExit))
  {
    PyObject *pRepr;
    PyErr_Fetch(&pType, &pValue, &pTraceback);
    pRepr = PyObject_Repr(pValue);
    *errstrp = string_sprintf("exited with errorlevel: %s",
                              PyString_AsString(pRepr));
    Py_DECREF(pRepr);
    Py_XDECREF(pType);
    Py_XDECREF(pValue);
    Py_XDECREF(pTraceback);
    return NULL;
  }
  /* Otherwise get the values, which clears the error data */
  PyErr_Fetch(&pType, &pValue, &pTraceback);
  if (pType)
  {
    PyObject *pMod, *pList, *pSep, *pJoin;
    pMod = PyImport_ImportModule("traceback");
    if (pMod)
    {
      PyObject *pRepr;
      pList = PyObject_CallMethod(pMod, "format_exception", "OOO",
                                  pType, pValue, pTraceback);
      pRepr = PyObject_Repr(pValue);
      pSep = PyUnicode_FromString("\n");
      pJoin = PyUnicode_Join(pSep, pList);

      DEBUG(D_any) debug_printf("%s", PyString_AsString(pJoin));
      if (opt_python_log_exceptions)
        *errstrp = string_sprintf("%s", PyString_AsString(pJoin));
      else
      {
        *errstrp = string_sprintf("Exception raised in python function: %s",
                                  PyString_AsString(pRepr));
      }

      Py_DECREF(pRepr);
      Py_XDECREF(pList);
      Py_XDECREF(pSep);
      Py_XDECREF(pJoin);
    }
    else
    {
      *errstrp = US"Error loading traceback module";
      PyErr_Clear(); /* Cleans up failed traceback import */
    }
  }
  Py_XDECREF(pType);
  Py_XDECREF(pValue);
  Py_XDECREF(pTraceback);
  return NULL;
}

/* When a python function returns a list, stringify each item in the
 * list and combine them into one big string, separated by the
 * configurable separator. */
static uschar *
string_from_python_object(PyObject *pResult, uschar *sep)
{
  uschar *list = US"";
  Py_ssize_t count = PyList_Size(pResult);
  int loop;
  int ptr = 0, size = 0;
  for (loop=0; loop < count; loop++)
  {
    PyObject *pItem;
    uschar *temp;
    pItem = PyList_GetItem(pResult, loop);
    temp = string_copy( (const uschar *)PyString_AsString(pItem));
    size = Ustrlen(temp);
    /* Swiped from expand.c to parse list items for the seperator
       character and double them if it finds them */
    for (;;)
    {
      size_t seglen = Ustrcspn(temp,sep);
      list = string_cat(list, &size, &ptr, temp, seglen + 1);
      /* If we got to the end of the string we output one character
         too many; backup and end the loop. Otherwise arrange to double
         the separator. */
      if(temp[seglen] == '\0') { ptr--; break; }
      list = string_cat(list, &size, &ptr, sep, 1);
      temp += seglen + 1;
    }
    /* Add separator preparing for next item in list */
    list = string_cat(list, &size, &ptr, sep, 1);
    Py_DECREF(pItem);
  }
  DEBUG(D_acl)
    debug_printf("Stringified python list has %d items and is %d characters long\n",
                 count, ptr);
  /* Remove the trailing separator */
  if (ptr > 0)
    list[ptr-1] = '\0';
  return list;
}

uschar *
init_python(uschar *startup_module)
{
  char *name, *mname, *path;
  PyObject *pName, *pPath;

  path  = basedir( CCS startup_module );
  name  = filename( CCS startup_module );
  mname = modulename( CCS name );

  Py_SetProgramName("Exim");
  Py_Initialize();
  /* Is a fatal error if it fails to initialize */
  if (!Py_IsInitialized())
    return(US"Error initializing Python interpreter");

  /* Add path of startup module code to system search path, but only if
   * the detected module name is actually specified in a location by the
   * python_startup configuration setting. */
  if (Ustrcmp(name, path) != 0 )
  {
    pPath = PySys_GetObject("path");
    if (pPath == NULL)
      return(string_sprintf("Error loading python sys.path object"));
    pName = PyString_FromString(path);
    if (PyList_Insert(pPath, 0, pName))
      return(string_sprintf("Error inserting subdir into sys.path"));
  }
  /* Create static functions expand_string, debug_write, and log_write */
  /* Process startup_code */
  pModule = PyImport_ImportModule(mname);
  if (pModule == NULL)
    return(string_sprintf("\nFailed to import module %s", mname));
  return NULL;
}

/* Cleanly close out everything python related. */
void
cleanup_python(void)
{
  if (pModule != NULL)
    Py_DECREF(pModule);
  if (Py_IsInitialized())
    Py_Finalize();
}

/* The python expansion comes into this function with the python
 * function to call and all args to that function, and a list seperator
 * to use in case the return value is a list. */
uschar *
call_python_cat(uschar *yield, int *sizep, int *ptrp, uschar **errstrp,
  uschar *sep, uschar *name, uschar **arg)
{
  uschar *str;
  size_t count = 0;
  int i;
  PyObject *pFunc, *pArgs, *pValue, *pReturn;

  if (!Py_IsInitialized())
    {
    *errstrp = US"Python interpreter not initialized";
    return NULL;
    }
  else if (pModule == NULL)
    {
    *errstrp = US"Python module not loaded";
    return NULL;
    }

  /* Identify and call appropriate function */
  pFunc = PyObject_GetAttrString(pModule, CCS name);
  if (pFunc && PyCallable_Check(pFunc))
  {
    PyCodeObject *pFuncCode = (PyCodeObject *)PyFunction_GET_CODE(pFunc);
    /* Should not fail if pFunc succeeded, but check to be thorough */
    if (!pFuncCode)
    {
      *errstrp = string_sprintf("Can't check function arg count for %s",
                                name);
      return NULL;
    }
    while(arg[count])
      count++;
    /* Sanity checking: Calling a python object requires to state number of
       vars being passed, bail if it doesn't match function declaration. */
    if (count != pFuncCode->co_argcount)
    {
      *errstrp = string_sprintf("Expected %d args to %s, was passed %d",
                                pFuncCode->co_argcount, name, count);
      return NULL;
    }
    pArgs = PyTuple_New(count);
    for (i = 0; i < count; ++i)
    {
      pValue = PyString_FromString(CCS arg[i]);
      PyTuple_SetItem(pArgs, i, pValue);
    }
    /* Call the function */
    pReturn = PyObject_CallObject(pFunc, pArgs);
    Py_DECREF(pArgs);
    if (pReturn != NULL)
    {
      /* Convert the appropriate format to a string and return it */
      if (PyInt_CheckExact(pReturn))
        str = string_sprintf("%d", PyInt_AsLong(pReturn));
      else if (PyLong_CheckExact(pReturn))
        str = string_sprintf("%lf", PyLong_AsLong(pReturn));
      else if (PyFloat_CheckExact(pReturn))
        str = string_sprintf("%f", PyFloat_AsDouble(pReturn));
      else if (PyString_CheckExact(pReturn))
        str = US PyString_AsString(pReturn);
      else if (PyList_CheckExact(pReturn))
        str = string_from_python_object(pReturn, sep);
      else
        str = US"Unknown object type returned";
      Py_DECREF(pFunc);
      Py_DECREF(pReturn);
    }
    else
    {
      handle_python_exception(name, errstrp);
      return NULL;
    }
  }
  else
  {
    *errstrp = string_sprintf("Did not find function '%s'", name);
    return NULL;
  }

  yield = string_cat(yield, sizep, ptrp, str, strlen(CCS str));
  return yield;
}

/* vim:tw=72 sw=2 ts=2 expandtab
 */
