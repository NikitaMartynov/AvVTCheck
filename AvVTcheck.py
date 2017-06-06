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
                params = {'apikey': _vt_api_key, 'resource': ltrunc_at(rtrunc_at(line, ';', 4), ';', 3)}
                response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                response_json = response.json()

                if response_json['response_code'] == 0:
                    print_line = line.strip("\n") + "; {0:s}\n".format(_not_present_in_vt)
                elif response_json['response_code'] == 1:
                    vendors_detected = get_vendors_detected(response_json)
                    if _the_reference_vendor not in vendors_detected:
                        detect = "No"
                    else:
                        detect = "Yes"
                    print_line = line.strip("\n") + "; {0:s}; {1:s}; {2:s}; {3:s}\n".format(detect,
                                                              str(response_json['positives']),
                                                              str(response_json['scan_date']),
                                                              vendors_detected)
                else:
                    print_line = line.strip("\n") + "{0:s} unexpected response code: {1:s}\n".format(line,
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
                                     epilog='Takes as input ";" separated file.')
    parser.add_argument('-i', '--input', default=True,
                        help="Input file including path.")
    parser.add_argument('-o', '--output', default=False,
                        help="Output file including path. Default: ./VT_hashes_processed.csv")

    parser.add_argument('-av', '--AVvendor', default=False,
                        help="Select your AV vendor as it is named in VT. Default: Microsoft")

    parser.add_argument('-ch', '--columnHashes', type=int, default=False,
                        help="Specify number of the column with hashes")

    parser.add_argument('-ct', '--columnsTotal', type=int, default=False,
                        help="Specify number of columns in total")
    args = parser.parse_args()

    if bool(args.input):
        _ifile = args.input
    if bool(args.output):
        _ofile = args.output
    else:
        _ofile = './VT_hashes_processed.csv'
    if bool(args.AVvendor):
        _the_reference_vendor = args.AVvendor
    else:
        _the_reference_vendor = "Microsoft"
    if bool(args.columnHashes):
        _columnHashes = args.columnHashes
    else:
        _columnHashes = 4
    if bool(args.columnsTotal):
        _columnsTotal = args.columnHashes
    else:
        _columnsTotal = 5

    query_report_on_hashes_from_vt()


if __name__ == "__main__":
    main()
