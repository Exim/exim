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

uschar *
init_python(uschar *startup_module)
{
  char *name = "python";
  // PyObject *pName, *pModule, *pDict, *pFunc;
  // PyObject *pArgs, *pValue;
  PyObject *pName, *pModule;

  Py_SetProgramName(name);
  Py_Initialize();
  /* Is a fatal error if it fails to initialize */
  if (!Py_IsInitialized())
    return(US"Error initializing Python interpreter");
  /* Create static functions expand_string, debug_write, and log_write */
  /* Process startup_code */
/*
  pName = PyString_FromString((char *)startup_module);
  if (pName == NULL)
  {
    PyErr_Print();
    fprintf(stderr, "Failed to open module \"%s\"\n", startup_module);
    //return(sprintf("Unable to open python script %s", (const char *)startup_module));
    return(US"Error opening python module");
  }
  pModule = PyImport_Import(pName);
  Py_DECREF(pName);
  if (pModule == NULL)
  {
    PyErr_Print();
    fprintf(stderr, "Failed to import \"%s\"\n", startup_module);
    return(US"Error importing python module");
  }
*/
  return NULL;
}

void
cleanup_python(void)
{
  if (Py_IsInitialized())
    Py_Finalize();
}

uschar *
call_python_cat(uschar *yield, int *sizep, int *ptrp, uschar **errstrp,
  uschar *name, uschar **arg)
{
  /* Identify and call appropriate function */
  return yield;
}

// vim:tw=72 sw=2 ts=2 expandtab
