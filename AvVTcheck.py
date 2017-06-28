#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
import argparse
import os
import requests

import time

_vt_api_key = ''

_not_present_in_vt = "not present"



def rtrunc_at(s, d, n=1):
    "Returns s truncated from the right at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[:n])


def ltrunc_at(s, d, n=1):
    "Returns s truncated from the left at the n'th (3rd by default) occurrence of the delimiter, d."
    return d.join(s.split(d)[n:])


def get_hash(line, ch, ct):
    if ch == ct:
        hash_val = ltrunc_at(line, ';', _columnHashes - 1)
    elif ch > ct:
        print exit("You cannot have parameter ch > ct. Make sure to type the input which makes sense!")
    else:
        hash_val = ltrunc_at(rtrunc_at(line, ';', _columnsTotal - 1), ';', _columnHashes - 1)
    if not hash_val.strip("\r\n"):
        print exit("Please verify your input. It seems that column #{0:s} has empty cells. All rows in this column "
                   "should have hashes".format(str(_columnHashes)))
    return hash_val


def get_vendors_detected(response_json):
    detected_vendors = ''
    for vendor in response_json['scans']:
        if response_json['scans'][vendor]['detected'] == True:
            detected_vendors += vendor + ' '
    return detected_vendors.rstrip(' ')


def query_report_on_hashes_from_vt():
    print 'Pulling reports on hashes from virustotal:\n'
    ifilename_full = _ifile
    ofilename_full = _ofile
    with open(ifilename_full, 'r') as fd:
        with open(ofilename_full, 'wb') as fd_out:
            for line in fd.readlines():
                hash_val = get_hash(line, _columnHashes, _columnsTotal)
                params = {'apikey': _vt_api_key, 'resource': hash_val}
                try:
                    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                except:
                    print exit("Failed to connect to VT. Check your internet connection.")
                response_json = response.json()

                if response_json['response_code'] == 0:
                    print_line = line.strip("\r\n") + "; {0:s}\n".format(_not_present_in_vt)
                elif response_json['response_code'] == 1:
                    vendors_detected = get_vendors_detected(response_json)
                    if _the_reference_vendor not in vendors_detected:
                        detect = "No"
                    else:
                        detect = "Yes"
                    print_line = line.strip("\r\n") + "; {0:s}; {1:s}; {2:s}; {3:s}\n".format(detect,
                                                              str(response_json['positives']),
                                                              str(response_json['scan_date']),
                                                              vendors_detected)
                else:
                    print_line = line.strip("\r\n") + "{0:s} unexpected response code: {1:s}\n".format(line,
                                                                                str(response_json['response_code']))
                fd_out.write(print_line)
                print print_line
                time.sleep(15)


def main():
    global _opath
    global _ifile
    global _ofile
    global _columnHashes
    global _columnsTotal
    global _the_reference_vendor

    # if not os.path.exists(_out_path):
    #     os.makedirs(_out_path)

    parser = argparse.ArgumentParser(prog='AvVTcheck', description='Checks hashes at VT against your selected AV.',
                                     epilog='Takes as input ";" separated csv file.')
    parser.add_argument('-i', '--input', default=False,
                        help="Mandatory: Input file including path.")
    parser.add_argument('-o', '--output', default='./VT_hashes_processed.csv',
                        help="Optional: Output file including path. Default: ./VT_hashes_processed.csv")

    parser.add_argument('-av', '--AVvendor', default="Microsoft",
                        help="Optional: Select your AV vendor as it is named in VT. Default: Microsoft")

    parser.add_argument('-ch', '--columnHashes', type=int, default=4,
                        help="Optional: Specify number of the column with hashes. Default = 4")

    parser.add_argument('-ct', '--columnsTotal', type=int, default=5,
                        help="Optional: Specify number of columns in total. Default = 5")
    args = parser.parse_args()

    if bool(args.output):
        _ofile = args.output
    if bool(args.AVvendor):
        _the_reference_vendor = args.AVvendor
    if bool(args.columnHashes):
        _columnHashes = args.columnHashes
    if bool(args.columnsTotal):
        _columnsTotal = args.columnsTotal
    if bool(args.input):
        _ifile = args.input
        query_report_on_hashes_from_vt()
    else:
        print "Invalid arguments, see help: AcVTcheck.py -h"


if __name__ == "__main__":
    main()
