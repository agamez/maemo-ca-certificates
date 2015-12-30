#!/usr/bin/python
# vim:set et sw=4:
#
# certdata2pem.py - splits certdata.txt into multiple files
#
# Copyright (C) 2009 Philipp Kern <pkern@debian.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301,
# USA.

import base64
import os.path
from os import mkdir
import re
import sys
import textwrap
import codecs
from array import array

objects = []

# Dirty file parser.
in_data, in_multiline, in_obj = False, False, False
field, type, value, obj = None, None, None, dict()

# Python 3 will not let us decode non-ascii characters if we
# have not specified an encoding, but Python 2's open does not
# have an option to set the encoding. Python 3's open is io.open
# and io.open has been backported to Python 2.6 and 2.7, but not
# to Python 2.5, which offers the alternate codecs.open
for line in codecs.open('certdata.txt', 'rt', encoding='utf8'):
    # Ignore the file header.
    if not in_data:
        if line.startswith('BEGINDATA'):
            in_data = True
        continue
    # Ignore comment lines.
    if line.startswith('#'):
        continue
    # Empty lines are significant if we are inside an object.
    if in_obj and len(line.strip()) == 0:
        objects.append(obj)
        obj = dict()
        in_obj = False
        continue
    if len(line.strip()) == 0:
        continue
    if in_multiline:
        if not line.startswith('END'):
            if type == 'MULTILINE_OCTAL':
                line = line.strip()
                for i in re.finditer(r'\\([0-3][0-7][0-7])', line):
                    value.append(int(i.group(1), 8))
            else:
                value += line
            continue
        obj[field] = value
        in_multiline = False
        continue
    if line.startswith('CKA_CLASS'):
        in_obj = True
    line_parts = line.strip().split(' ', 2)
    if len(line_parts) > 2:
        field, type = line_parts[0:2]
        value = ' '.join(line_parts[2:])
    elif len(line_parts) == 2:
        field, type = line_parts
        value = None
    else:
        raise NotImplementedError('line_parts < 2 not supported.')
    if type == 'MULTILINE_OCTAL':
        in_multiline = True
        value = array('B')
        continue
    obj[field] = value
if len(obj) > 0:
    objects.append(obj)

# Create output dirs
mkdir("common-ca")
mkdir("blacklist")

# Build up trust database.
trust = dict()
for obj in objects:
    obj['DIRNAME'] = 'common-ca'
    if obj['CKA_CLASS'] not in ('CKO_NETSCAPE_TRUST', 'CKO_NSS_TRUST'):
        continue
    if obj['CKA_TRUST_SERVER_AUTH'] in ('CKT_NETSCAPE_TRUSTED_DELEGATOR',
                                          'CKT_NSS_TRUSTED_DELEGATOR'):
        trust[obj['CKA_LABEL']] = True
    elif obj['CKA_TRUST_EMAIL_PROTECTION'] in ('CKT_NETSCAPE_TRUSTED_DELEGATOR',
                                               'CKT_NSS_TRUSTED_DELEGATOR'):
        trust[obj['CKA_LABEL']] = True
    elif obj['CKA_TRUST_SERVER_AUTH'] in ('CKT_NETSCAPE_UNTRUSTED',
                                          'CKT_NSS_NOT_TRUSTED'):
        print('!'*74)
        print("UNTRUSTED CERTIFICATE FOUND: %s" % obj['CKA_LABEL'])
        print('!'*74)
        obj['DIRNAME'] = 'blacklist'
    else:
        print("Ignoring certificate %s.  SAUTH=%s, EPROT=%s" % \
              (obj['CKA_LABEL'], obj['CKA_TRUST_SERVER_AUTH'],
               obj['CKA_TRUST_EMAIL_PROTECTION']))

for obj in objects:
    if obj['CKA_CLASS'] == 'CKO_CERTIFICATE':
        if not obj['CKA_LABEL'] in trust or not trust[obj['CKA_LABEL']]:
            continue
        bname = obj['DIRNAME'] + '/' + obj['CKA_LABEL'][1:-1].replace('/', '_')\
                                      .replace(' ', '_')\
                                      .replace('(', '=')\
                                      .replace(')', '=')\
                                      .replace(',', '_')

        # this is the only way to decode the way NSS stores multi-byte UTF-8
        # and we need an escaped string for checking existence of things
        # otherwise we're dependant on the user's current locale.

        # Python 2
        # Convert the unicode string back to its original byte form
        # (contents of files returned by io.open are returned as
        #  unicode strings)
        # then to an escaped string that can be passed to open()
        # and os.path.exists()
        bname = bname.encode('utf-8').decode('string_escape')

        fname = bname + r'.crt'
        if os.path.exists(fname):
            print("Found duplicate certificate name %s, renaming." % bname)
            fname = bname + r'_2.crt'
        f = open(fname, 'w')
        f.write("-----BEGIN CERTIFICATE-----\n")
        f.write(base64.encodestring(obj['CKA_VALUE']))
        f.write("-----END CERTIFICATE-----\n")

