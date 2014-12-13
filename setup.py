# -*- coding: utf-8 -*-
#
# © Лаборатория 50, 2014
# Автор: Шлыков Василий vash@vasiliyshlykov.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from distutils.core import setup, Extension

setup (
    name = "parsec",
    version = "0.3",
    description = "python binding to PARSEC API",
    long_description = """
Эта библиотека для языка Питон содержит функции работы с API PARSEC.
PARSEC входит в систему защиты ОС СН Astra Linux Special Edition. В основном
это функции мандатной защиты объектов операционной системы: процессов, файлов,
сокетов и т.д.

Пакет содержит набор Питоновских биндингов для API PARSEC.
""",
    author = "Лаборатория 50",
    author_email = "team@lab50.net",
    url = "http://lab50.net",

    license = "LGPLv3+",

    classifiers=[
           'Development Status :: 4 - Beta'
           'Environment :: Console',
           'Intended Audience :: Developers',
           'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
           'Operating System :: POSIX :: Linux',
           'Natural Language :: Russian',
           'Programming Language :: C',
           'Programming Language :: Python :: 2.7',
           'Programming Language :: Python :: 3',
           'Programming Language :: Python :: Implementation :: CPython',
           'Topic :: Security',
           'Topic :: Software Development :: Libraries :: Python Modules',
    ],
 
    ext_modules = [
        Extension(
            "parsec",
            sources = ['parsec.c'],
            libraries=['parsec-mac'],
            #extra_compile_args = commands.getoutput("krb5-config --cflags gssapi").split(),
        ),
    ],
)
