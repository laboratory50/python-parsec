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
#include <parsec/parsec_mac.h>
#include <parsec/parsec_cap.h>
#include <parsec/mac.h>
#include <parsec/parsec_integration.h>
#include <sys/prctl.h>

#if PY_MAJOR_VERSION < 3
    #define PyLong_FromLong PyInt_FromLong
#endif

PyObject* raise_exception(void);

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

static PyObject* py_mac_to_text(PyObject *self, PyObject *args)
{
  mac_t mac = NULL;
  int flags = 0;
  char *str;
  PyObject *ret;

  if (!PyArg_ParseTuple(args, "O&|i:mac_to_text",
            get_mac, &mac, &flags))
      return NULL;

  str = mac_to_text(mac, NULL, flags);

  if (!str)
      return raise_exception();

  ret = Py_BuildValue("s", str);
  free(str);

  return ret;
}

static PyObject* py_mac_from_text(PyObject *self, PyObject *args)
{
  mac_t mac = NULL;
  const char *str = NULL;
  mac_type_t type = MAC_TYPE_OBJECT;

  if (!PyArg_ParseTuple(args, "s|i:mac_from_text", &str, &type))
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

  if (!PyArg_ParseTuple(args, "iO&:mac_set_pid", &pid, get_mac, &mac))
      return NULL;

  if (mac_set_pid(pid, mac) == -1)
      return raise_exception();

  Py_RETURN_NONE;
}

static PyObject* py_mac_cmp(PyObject *self, PyObject *args)
{
  mac_t src = NULL,
        dst = NULL;
  int ret;

  if (!PyArg_ParseTuple(args, "O&O&:mac_cmp", get_mac, &src, get_mac, &dst))
      return NULL;

  ret = mac_cmp(src, dst);

  return Py_BuildValue("i", ret);
}

static PyObject* py_mac_get_fd(PyObject *self, PyObject *args)
{
  mac_t mac;
  int fd = 0;

  if (!PyArg_ParseTuple(args, "i:mac_get_fd", &fd))
      return NULL;

  mac = mac_get_fd(fd);
  if (!mac)
      return raise_exception();

  return mac_to_py(mac);
}

static PyObject* py_drop_caps(PyObject *self)
{
  if (parsec_cur_caps_set(0, 0) != 0)
      return raise_exception();

  Py_RETURN_NONE;
}

/*
 * Считывание привилегий процесса.
 * Возвращает кортеж (effective, permitted, inheritable).
 */
static PyObject* py_capget(PyObject *self, PyObject *args)
{
  pid_t pid = 0;
  parsec_caps_t caps;

  if (!PyArg_ParseTuple(args, "i:capget", &pid))
      return NULL;

  if (parsec_capget(pid, &caps) == -1)
      return raise_exception();

  return Py_BuildValue("(iii)", caps.cap_effective,
                       caps.cap_permitted, caps.cap_inheritable);
}

/*
 * Установка привилегий на процесс.
 * Параметры: pid, (effective, permitted, inheritable)
 */
static PyObject* py_capset(PyObject *self, PyObject *args)
{
  pid_t pid = 0;
  parsec_caps_t caps;

  if (!PyArg_ParseTuple(args, "i(iii):capset", &pid, &caps.cap_effective,
                        &caps.cap_permitted, &caps.cap_inheritable))
      return NULL;

  if (parsec_capset(pid, &caps) == -1)
      return raise_exception();

  Py_RETURN_NONE;
}

/*
 * Установка флага KEEPCAPS на процесс.
 * Параметры: True или False
 */
static PyObject* py_set_keepcaps(PyObject *self, PyObject *args)
{
  PyObject *obj;
  if (!PyArg_ParseTuple(args, "O:set_keepcaps", &obj))
      return NULL;

  int val = PyObject_IsTrue(obj);

  if(val == -1)
  {
    PyErr_SetString(PyExc_TypeError, "Can't convert to True or False");
    return NULL;
  }

  if(prctl(PR_SET_KEEPCAPS, val) == -1)
      return raise_exception();

  Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
  {"mac_to_text",   (PyCFunction) py_mac_to_text, METH_VARARGS,
   "Преобразование объекта-метки в текстовый формат."},
  {"mac_from_text", (PyCFunction) py_mac_from_text, METH_VARARGS,
   "Преобразование текста в мандатную метку."},
  {"mac_get_pid",   (PyCFunction) py_mac_get_pid, METH_VARARGS,
   "Считывание мандатного контекста безопасности процесса."},
  {"mac_set_pid",   (PyCFunction) py_mac_set_pid, METH_VARARGS,
   "Установка мандатного контекста безопасности процесса."},
  {"mac_cmp",       (PyCFunction) py_mac_cmp, METH_VARARGS,
   "Сравнение мандатных меток."},
  {"mac_get_fd",    (PyCFunction) py_mac_get_fd, METH_VARARGS,
   "Считывание мандатной метки файлового объекта (или сокета)."},
  {"drop_caps",     (PyCFunction) py_drop_caps, METH_NOARGS,
   "Сброс всех привилегий Linux и PARSEC у текущего процесс."},
  {"capget",        (PyCFunction) py_capget, METH_VARARGS,
   "Считывание привилегий PARSEC процесса."},
  {"capset",        (PyCFunction) py_capset, METH_VARARGS,
   "Установка привилегий PARSEC процесса."},
  {"set_keepcups",  (PyCFunction) py_set_keepcaps, METH_VARARGS,
   "Установка флага KEEPCAPS процесса."},
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
  m = PyModule_Create(&moduledef);
#else
  m = Py_InitModule("parsec", methods);
#endif

  if (m == NULL)
      return NULL;

  d = PyModule_GetDict(m);

  PyDict_SetItemString(d, "FMT_NUM", PyLong_FromLong(MAC_FMT_NUM));
  PyDict_SetItemString(d, "FMT_TXT", PyLong_FromLong(MAC_FMT_TXT));
  PyDict_SetItemString(d, "FMT_LEV", PyLong_FromLong(MAC_FMT_LEV));
  PyDict_SetItemString(d, "FMT_CAT", PyLong_FromLong(MAC_FMT_CAT));
  PyDict_SetItemString(d, "FMT_TYPE", PyLong_FromLong(MAC_FMT_TYPE));

  PyDict_SetItemString(d, "MAC_TYPE_SUBJECT", PyLong_FromLong(MAC_TYPE_SUBJECT));
  PyDict_SetItemString(d, "MAC_TYPE_OBJECT", PyLong_FromLong(MAC_TYPE_OBJECT));
  PyDict_SetItemString(d, "MAC_TYPE_EQU", PyLong_FromLong(MAC_TYPE_EQU));
  PyDict_SetItemString(d, "MAC_TYPE_LOW", PyLong_FromLong(MAC_TYPE_LOW));
  PyDict_SetItemString(d, "MAC_TYPE_EQU_W", PyLong_FromLong(MAC_TYPE_EQU_W));

  PyDict_SetItemString(d, "PCAP_FILE_CAP",   PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_FILE_CAP)));
  PyDict_SetItemString(d, "PCAP_AUDIT",      PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_AUDIT)));
  PyDict_SetItemString(d, "PCAP_SETMAC",     PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_SETMAC)));
  PyDict_SetItemString(d, "PCAP_CHMAC",      PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_CHMAC)));
  PyDict_SetItemString(d, "PCAP_IGNMACLVL",  PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_IGNMACLVL)));
  PyDict_SetItemString(d, "PCAP_IGNMACCAT",  PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_IGNMACCAT)));
  PyDict_SetItemString(d, "PCAP_SIG",        PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_SIG)));
  PyDict_SetItemString(d, "PCAP_PRIV_SOCK",  PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_PRIV_SOCK)));
  PyDict_SetItemString(d, "PCAP_READSEARCH", PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_READSEARCH)));
  PyDict_SetItemString(d, "PCAP_CAP",        PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_CAP)));
  PyDict_SetItemString(d, "PCAP_MAC_SOCK",   PyLong_FromLong(PARSEC_CAP_TO_MASK(PARSEC_CAP_MAC_SOCK)));

  return m; /* m might be NULL if module init failed */
}

#if PY_MAJOR_VERSION >= 3
extern PyMODINIT_FUNC PyInit_parsecmod(void);

PyMODINIT_FUNC PyInit_parsecmod(void)
{
  return moduleinit();
}
#else
extern PyMODINIT_FUNC initparsec(void);

PyMODINIT_FUNC initparsec(void)
{
  moduleinit();
}
#endif

