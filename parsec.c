/**
 * © Лаборатория 50, 2014
 * Автор: Шлыков Василий vash@vasiliyshlykov.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <Python.h>
#include <parsec/mac.h>

/** Деструктор для капсулы */
static void free_pymac(PyObject *pyobj)
{
  mac_t mac;

  if (get_mac(pyobj, &mac) == 0)
      return;

  mac_free(mac);
}

inline static PyObject* mac_to_py(mac_t mac)
{
  return PyCapsule_New(mac, "parsec_h", &free_pymac);
}

PyObject* new_pymac(mac_type_t type)
{
  mac_t mac = mac_init(type);

  if (!mac)
      return raise_exception();

  return mac_to_py(mac);
}

/** Создание питоновского исключения в соответствии с кодом errno */
PyObject* raise_exception(void)
{
  PyObject *exc; 

  switch (errno)
    {
      case ENOMEM: exc = PyExc_MemoryError; break;
      case EINVAL: exc = PyExc_ValueError; break;
      default: exc = PyExc_OSError;
    }

  return PyErr_SetFromErrno(exc);
}

/** Конвертор PyObject -> mac_t для функций PyArg_ParseTuple*. */
static int get_mac(PyObject *pyobj, mac_t* mac)
{
  if (!PyCapsule_IsValid(pyobj, "parsec_h"))
    {
      PyErr_SetString(PyExc_TypeError, "Expected a PARSEC mac_t object");
      return 0;
    }
  else
    {
      *mac = PyCapsule_GetPointer(pyobj, "parsec_h");
      return 1;
    }
}

static PyObject* py_mac_to_text(PyObject *self, PyObject *args, PyObject *kw)
{
  mac_t mac = NULL;
  int flags = 0;
  char *str;
  PyObject *ret;
  static char *kwlist[] = { "fmt_flags", NULL };

  if (!PyArg_ParseTupleAndKeywords(args, kw, "O&|i:mac_to_text", kwlist,
	      get_mac, &mac, &flags))
      return NULL;

  str = mac_to_text(mac, NULL, flags);

  if (!str)
      return raise_exception();

  ret = Py_BuildValue("s", str);
  free(str);

  return ret;
}

static PyObject* py_mac_from_text(PyObject *self, PyObject *args, PyObject *kw)
{
  mac_t mac = NULL;
  const char *str = NULL;
  mac_type_t type = MAC_TYPE_OBJECT;
  static char *kwlist[] = { "mac_type", NULL };

  if (!PyArg_ParseTupleAndKeywords(args, kw, "s|i:mac_from_text", kwlist,
	      &str, &type))
      return NULL;

  if (!str)
    {
      PyErr_SetString(PyExc_ValueError, "String shouldn't be None");
      return NULL;
    }

  mac = mac_init(type);
  if (!mac)
      return raise_exception();

  if (mac_from_text(mac, str) == -1)
      return raise_exception();

  return mac_to_py(mac);
}

static PyObject* py_mac_get_pid(PyObject *self, PyObject *args)
{
  mac_t mac;
  pid_t pid = 0;

  if (!PyArg_ParseTuple(args, "i:mac_get_pid", &pid))
      return NULL;

  mac = mac_get_pid(pid);
  if (!mac)
      return raise_exception();

  return mac_to_py(mac);
}

static PyObject* py_mac_set_pid(PyObject *self, PyObject *args)
{
  mac_t mac = NULL;
  pid_t pid = 0;

  if (!PyArg_ParseTuple(args, "iO&:mac_set_pid", pid, get_mac, &mac))
      return NULL;

  if (mac_set_pid(pid, mac) == -1)
      return raise_exception();

  Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
  {"mac_to_text",  py_mac_to_text, METH_VARARGS | METH_KEYWORDS,
   "Преобразование объекта-метки в текстовый формат."},
  {"mac_from_text",  py_mac_from_text, METH_VARARGS | METH_KEYWORDS,
   "Преобразование текста в мандатную метку."},
  {"mac_get_pid",  py_mac_get_pid, METH_VARARGS,
   "Считывание мандатного контекста безопасности процесса."},
  {"mac_set_pid",  py_mac_set_pid, METH_VARARGS,
   "Установка мандатного контекста безопасности процесса."},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
  PyModuleDef_HEAD_INIT,
  "parsec",              /* m_name */
  "parsec  module",      /* m_doc */
  -1,                    /* m_size */
  methods,               /* m_methods */
  NULL,                  /* m_reload */
  NULL,                  /* m_traverse */
  NULL,                  /* m_clear */
  NULL,                  /* m_free */
};
#endif

static PyObject* moduleinit(void)
{
  PyObject *m, *d;

#if PY_MAJOR_VERSION >= 3
  m = PyModule_Create (&moduledef);
#else
  m = Py_InitModule ((char *) "parsec", methods);
#endif

  d = PyModule_GetDict(m);

  PyDict_SetItemString(d, "FMT_NUM", PyInt_FromLong(MAC_FMT_NUM));
  PyDict_SetItemString(d, "FMT_TXT", PyInt_FromLong(MAC_FMT_TXT));
  PyDict_SetItemString(d, "FMT_LEV", PyInt_FromLong(MAC_FMT_LEV));
  PyDict_SetItemString(d, "FMT_CAT", PyInt_FromLong(MAC_FMT_CAT));
  PyDict_SetItemString(d, "FMT_TYPE", PyInt_FromLong(MAC_FMT_TYPE));

  PyDict_SetItemString(d, "MAC_TYPE_SUBJECT", PyInt_FromLong(MAC_TYPE_SUBJECT));
  PyDict_SetItemString(d, "MAC_TYPE_OBJECT", PyInt_FromLong(MAC_TYPE_OBJECT));
  PyDict_SetItemString(d, "MAC_TYPE_EQU", PyInt_FromLong(MAC_TYPE_EQU));
  PyDict_SetItemString(d, "MAC_TYPE_LOW", PyInt_FromLong(MAC_TYPE_LOW));
  PyDict_SetItemString(d, "MAC_TYPE_EQU_W", PyInt_FromLong(MAC_TYPE_EQU_W));

  return m; /* m might be NULL if module init failed */
}

#if PY_MAJOR_VERSION >= 3
extern PyMODINIT_FUNC PyInit_parsecmod(void);

PyMODINIT_FUNC PyInit_parsecmod(void)
{
  return moduleinit();
}
#else
extern void initparsecmod(void);

void initparsecmod(void)
{
  moduleinit();
}
#endif
