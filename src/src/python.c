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

uschar *
init_python(uschar *startup_module)
{
  char *name, *mname, *path;
  PyObject *pName, *pPath;

  path  = basedir( CCS startup_module );
  name  = filename( CCS startup_module );
  mname = modulename( CCS name );

  Py_SetProgramName("exim");
  Py_Initialize();
  /* Is a fatal error if it fails to initialize */
  if (!Py_IsInitialized())
    return(US"Error initializing Python interpreter");

  /* Add path of startup module code to system search path, but only if
   * the detected module name is actually specified in a location by the
   * python_startup configuration setting. */
  if (strncmp(name, path, sizeof(name)) != 0 )
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

void
cleanup_python(void)
{
  if (pModule != NULL)
    Py_DECREF(pModule);
  if (Py_IsInitialized())
    Py_Finalize();
}

uschar *
call_python_cat(uschar *yield, int *sizep, int *ptrp, uschar **errstrp,
  uschar *name, uschar **arg)
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
      else
        str = US PyString_AsString(pReturn);
    }
    else
    {
      *errstrp = string_sprintf("Did not get an answer from %s", name);
      return NULL;
    }
    Py_DECREF(pFunc);
    Py_DECREF(pReturn);
  }
  else
  {
    *errstrp = string_sprintf("Did not find function %s", name);
    return NULL;
  }

  yield = string_cat(yield, sizep, ptrp, str, strlen(CCS str));
  return yield;
}

// vim:tw=72 sw=2 ts=2 expandtab
