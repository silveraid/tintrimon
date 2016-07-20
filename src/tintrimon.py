#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#  Copyright (c) 2016 Frank Felhoffer
#
#  Permission is hereby granted, free of charge, to any person obtaining a
#  copy of this software and associated documentation files (the "Software"),
#  to deal in the Software without restriction, including without limitation
#  the rights to use, copy, modify, merge, publish, distribute, sublicense,
#  and/or sell copies of the Software, and to permit persons to whom the
#  Software is furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included
#  in all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
#  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
#  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#

"""
Python program to monitor Tintri Storage Appliances
"""

from __future__ import print_function

import argparse
import json
import sys

import tintri_1_1 as tintri
# from prettytable import PrettyTable



# Version information
build_ver = 'v0.01-ALPHA'
build_date = 'XXXX-XX-XX'


def parse_args():

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-s', '--host', required=True, action='store', help='')
    parser.add_argument('-u', '--user', required=True, action='store', help='')
    parser.add_argument('-p', '--password', required=True, action='store', help='')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', help='')
    args = parser.parse_args()
    return args


def main():

    args = parse_args()
    print("---")

    # Get the product name
    try:
        r = tintri.api_version(args.host)
        json_info = r.json()
        product_name = json_info['productName']
        print(product_name)

        # Login to Tintri VMStore
        session_id = tintri.api_login(args.host, args.user, args.password)

    except tintri.TintriRequestsException as tre:
        print_error(tre.__str__())
        exit(-2)

    except tintri.TintriApiException as tae:
        print_error(tae.__str__())
        exit(-3)


# Start program
if __name__ == "__main__":
    main()