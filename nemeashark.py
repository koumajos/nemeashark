#!/usr/bin/python3
"""[summary]
"""

# Standard libraries imports
import sys
import ipaddress
import argparse
from argparse import RawTextHelpFormatter

from tabulate import tabulate
from sty import fg, bg, ef, rs

# Third party imports

# NEMEA system library
import pytrap

HEADER = [
    "DST_MAC",
    "DST_IP",
    "DST_PORT",
    "SRC_MAC",
    "SRC_IP",
    "SRC_PORT",
    "PACKETS",
    "BYTES",
]
TYPES = ["mac", "ip", "port", "mac", "ip", "port", "packets", "bytes"]
COLORS = {
    "red": bg.da_red,
    "yellow": bg.da_yellow,
    "blue": bg.da_blue,
    "magenta": bg.da_magenta,
}


def load_pytrap(argv):
    """Init nemea libraries and set format of IP flows.
    Returns:
        tuple: Return tuple of rec and trap. Where rec is template of IP flows and trap is initialized pytrap NEMEA library.
    """
    trap = pytrap.TrapCtx()
    trap.init(argv, 1, 0)  # argv, ifcin - 1 input IFC, ifcout - 0 output IFC
    # Set the list of required fields in received messages.
    # This list is an output of e.g. flow_meter - basic flow.
    inputspec = "macaddr DST_MAC,macaddr SRC_MAC,ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT"
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
    rec = pytrap.UnirecTemplate(inputspec)
    return rec, trap


def parse_arguments(dependency=False):
    """Function for set arguments of module.
    Returns:
        argparse: Return setted argument of module.
    """
    parser = argparse.ArgumentParser(
        description="""Provides view on ip flow or biflow that was getted from network interface by NEMEA system from CESNET. 
 Special functions:
  1) color markering
  2) filtering
  3) sorting
 
    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i",
        help='Specification of interface types and their parameters, see "-h trap" (mandatory parameter).',
        type=str,
        metavar="IFC_SPEC",
    )

    parser.add_argument("-v", help="Be verbose.", action="store_true")

    parser.add_argument("-vv", help="Be more verbose.", action="store_true")

    parser.add_argument("-vvv", help="Be even more verbose.", action="store_true")

    parser.add_argument(
        "-m",
        "--mark",
        help="Mark some specific value. Example 1: ip:192.168.0.1 will mark every ip addres 192.168.0.1 with RED. Posible types: ip|mac|port|packets|bytes",
        type=str,
        nargs="+",
        metavar="<type:value>",
        default=[],
    )
    parser.add_argument(
        "-f",
        "--filter",
        help="Filter some specific flow. Example 1: 'ip:192.168.0.1&&port:53' will filer every flow where is ip addres 192.168.0.1 and port 53 in same flow. Can be use locical OR (||) and AND (&&) and brackets (), but when OR is placed you must filter wrap in quotations marks. Posible types: ip|mac|port|packets|bytes. There are also slecial filters: ipv4|ipv6|broadcast",
        type=str,
        metavar="<type:value>",
        default=None,
    )
    parser.add_argument(
        "-n",
        help="Number of flows that will be showed with one header. Default value is 46 lines, that is approximately one less command page.",
        type=int,
        default=46,
    )
    parser.add_argument(
        "-s",
        "--sort",
        help="Sort n flow (from parameter -n, recomanded usage with -n 0) by criterion. Posible criterions are ip|mac|port|packets|bytes.",
        type=str,
        metavar="<criterion>",
        default=None,
    )
    arg = parser.parse_args()
    return arg


def color_output(data, marks, size):
    dic_marks = {}
    for mark in marks:
        tmp = mark.split(":")
        if len(tmp) == 2:
            t, v = tmp
            c = "red"
        else:
            t, v, c = tmp
        if t in dic_marks:
            dic_marks[t].append((v, c))
        else:
            dic_marks[t] = [(v, c)]
    bg_color = True
    for i in range(0, len(data)):
        if bg_color is True:
            for j in range(0, 8):
                start = ""
                end = ""
                if j == 0:
                    start = f"{bg.da_green}"
                if j == 7:
                    end = f"{bg.rs}"
                if TYPES[j] in dic_marks:
                    for value in dic_marks[TYPES[j]]:
                        if value[0] == data[i][j]:
                            tmp = COLORS[value[1]]
                            start += f"{bg.rs}{tmp}"
                            end += f"{bg.rs}{bg.da_green}"
                data[i][j] = f"{start}{data[i][j]}{end}"
            bg_color = False
        else:
            for j in range(0, 8):
                start = ""
                end = ""
                if j == 0:
                    start = f"{bg.da_cyan}"
                if j == 7:
                    end = f"{bg.rs}"
                if TYPES[j] in dic_marks:
                    for value in dic_marks[TYPES[j]]:
                        if value[0] == data[i][j]:
                            tmp = COLORS[value[1]]
                            start += f"{bg.rs}{tmp}"
                            end += f"{bg.rs}{bg.da_cyan}"
                data[i][j] = f"{start}{data[i][j]}{end}"
            bg_color = True
    return data


def create_output(data, marks, size):
    # table = columnar(data, HEADER, no_borders=True)
    data = color_output(data, marks, size)
    table = tabulate(data, headers=HEADER)
    print(table)


def filter_output(rec, filters):
    logical_or = filters.split("||")
    logical_value = False
    for o in logical_or:
        logical_and = o.split("&&")
        tmp = True
        for f in logical_and:
            if f == "ipv4":
                if ipaddress.ip_address(str(rec.DST_IP)).version != 4:
                    tmp = False
                    break
            elif f == "ipv6":
                if ipaddress.ip_address(str(rec.DST_IP)).version != 6:
                    tmp = False
                    break
            elif f == "broadcast":
                pass
            else:
                t, v = f.split(":")
                if t == "ip":
                    if str(rec.DST_IP) != v and str(rec.SRC_IP) != v:
                        tmp = False
                        break
                elif t == "mac":
                    if str(rec.DST_MAC) != v and str(rec.SRC_MAC) != v:
                        tmp = False
                        break
                elif t == "port":
                    if str(rec.DST_PORT) != v and str(rec.SRC_PORT) != v:
                        tmp = False
                        break
                elif t == "packets":
                    if str(rec.PACKETS) != v:
                        tmp = False
                        break
                elif t == "bytes":
                    if str(rec.BYTES) != v:
                        tmp = False
                        break
        if tmp is True:
            return False
    return True


def main():
    """Main function of the module."""
    arg = parse_arguments()
    rec, trap = load_pytrap(sys.argv)
    biflow = None

    array = []
    while True:  # main loop for load ip-flows from interfaces
        try:  # load IP flow from IFC interface
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmttype, inputspec = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(inputspec)
            data = e.data
            biflow = None
        if len(data) <= 1:
            break
        rec.setData(data)  # set the IP flow to created tempalte

        if biflow is None:
            try:
                packets = rec.PACKETS_REV
                biflow = True
                # print("Use biflow")
            except AttributeError as e:
                biflow = False
                # print("Use flow")

        if arg.filter is not None and filter_output(rec, arg.filter) is True:
            continue

        d = [
            str(rec.DST_MAC),
            str(rec.DST_IP),
            str(rec.DST_PORT),
            str(rec.SRC_MAC),
            str(rec.SRC_IP),
            str(rec.SRC_PORT),
            str(rec.PACKETS),
            str(rec.BYTES),
        ]
        array.append(d)
        if arg.n != 0 and len(array) == arg.n:
            create_output(array, arg.mark, arg.n)
            array = []

    create_output(array, arg.mark, arg.n)
    trap.finalize()  # Free allocated TRAP IFCs


if __name__ == "__main__":
    main()
