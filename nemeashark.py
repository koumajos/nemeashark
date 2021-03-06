#!/usr/bin/python3
"""[summary]
"""

# Standard libraries imports
import sys
import csv
import ipaddress
import argparse
from argparse import RawTextHelpFormatter
from datetime import datetime

from tabulate import tabulate
from sty import fg, bg, ef, rs

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
    "TIME_FIRST",
    "TIME_LAST",
    "PROTOCOL",
    "TCP_FLAGS",
]
HEADER_BASICPLUS = ["IP_TTL", "IP_FLG", "TCP_WIN", "TCP_OPT", "TCP_MSS", "TCP_SYN_SIZE"]
HEADER_HTTP = [
    "HTTP_REQUEST_METHOD",
    "HTTP_REQUEST_HOST",
    "HTTP_REQUEST_URL",
    "HTTP_REQUEST_AGENT",
    "HTTP_REQUEST_REFERER",
    "HTTP_RESPONSE_STATUS_CODE",
    "HTTP_RESPONSE_CONTENT_TYPE ",
]
TYPES = [
    "mac",
    "ip",
    "port",
    "mac",
    "ip",
    "port",
    "packets",
    "bytes",
    "time",
    "time",
    "protocol",
    "tcl_flags",
]
TYPES_BASICPLUS = ["ttl", "ip_flg", "tcp_win", "tcp_opt", "tcp_mss", "tcp_syn_size"]
TYPES_HTTP = [
    "method",
    "host",
    "url",
    "useragent",
    "referer",
    "status_code",
    "content_type",
]
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
        "-p",
        "--plugins",
        help="Plugins of ipfixprobe of nemea system",
        type=str,
        nargs="+",
        metavar="plugin",
        default=[],
    )

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
        default=44,
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


def color_output(data, marks, size, header_size, types):
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
            for j in range(0, header_size):
                start = ""
                end = ""
                if j == 0:
                    start = f"{bg.da_green}"
                if j == header_size - 1:
                    end = f"{bg.rs}"
                if types[j] in dic_marks:
                    for value in dic_marks[types[j]]:
                        if value[0] == data[i][j]:
                            tmp = COLORS[value[1]]
                            start += f"{bg.rs}{tmp}"
                            end += f"{bg.rs}{bg.da_green}"
                data[i][j] = f"{start}{data[i][j]}{end}"
            bg_color = False
        else:
            for j in range(0, header_size):
                start = ""
                end = ""
                if j == 0:
                    start = f"{bg.da_cyan}"
                if j == header_size - 1:
                    end = f"{bg.rs}"
                if types[j] in dic_marks:
                    for value in dic_marks[types[j]]:
                        if value[0] == data[i][j]:
                            tmp = COLORS[value[1]]
                            start += f"{bg.rs}{tmp}"
                            end += f"{bg.rs}{bg.da_cyan}"
                data[i][j] = f"{start}{data[i][j]}{end}"
            bg_color = True
    return data


def create_output(data, marks, size, header, types):
    data = color_output(data, marks, size, len(header), types)
    table = tabulate(data, headers=header)
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


def basic_plugin(rec, biflow):
    packets = int(rec.PACKETS)
    byte = int(rec.BYTES)
    tcp_flags = str(rec.TCP_FLAGS)
    if biflow is True:
        packets += int(rec.PACKETS_REV)
        byte += int(rec.BYTES_REV)
        tcp_falgs = f"{tcp_flags};{rec.TCP_FLAGS_REV}"
    protocol = str(rec.PROTOCOL)
    with open("data/protocol_numbers.csv") as csvfile:
        spamreader = csv.reader(csvfile)
        for row in spamreader:
            if row[0] == protocol:
                protocol = row[1]
    d = [
        str(rec.SRC_MAC),
        str(rec.SRC_IP),
        str(rec.SRC_PORT),
        str(rec.DST_MAC),
        str(rec.DST_IP),
        str(rec.DST_PORT),
        str(packets),
        str(byte),
        datetime.utcfromtimestamp(float(str(rec.TIME_FIRST))).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )[:-4],
        datetime.utcfromtimestamp(float(str(rec.TIME_LAST))).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )[:-4],
        protocol,
        tcp_flags,
    ]
    return d


def basicplus_plugin(rec):
    return [
        f"{str(rec.IP_TTL)};{str(rec.IP_TTL_REV)}",
        f"{rec.IP_FLG};{rec.IP_FLG_REV}",
        f"{rec.TCP_WIN};{rec.TCP_WIN_REV}",
        f"{rec.TCP_OPT};{rec.TCP_OPT_REV}",
        f"{rec.TCP_MSS};{rec.TCP_MSS_REV}",
        f"{rec.TCP_SYN_SIZE}",
    ]


def http_plugin(rec):
    return [
        str(rec.HTTP_REQUEST_METHOD),
        str(rec.HTTP_REQUEST_HOST),
        str(rec.HTTP_REQUEST_URL),
        str(rec.HTTP_REQUEST_AGENT),
        str(rec.HTTP_REQUEST_REFERER),
        str(rec.HTTP_RESPONSE_STATUS_CODE),
        str(rec.HTTP_RESPONSE_CONTENT_TYPE),
    ]


def make_header(plugins):
    header = HEADER
    types = TYPES
    if "basicplus" in plugins:
        header = header + HEADER_BASICPLUS
        types = types + TYPES_BASICPLUS
    if "http" in plugins:
        header = header + HEADER_HTTP
        types = types + TYPES_HTTP
    return header, types


def main():
    """Main function of the module."""
    arg = parse_arguments()
    rec, trap = load_pytrap(sys.argv)
    biflow = None
    basicplus = None

    header, types = make_header(arg.plugins)
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

        row = basic_plugin(rec, biflow)
        if "basicplus" in arg.plugins:
            row = row + basicplus_plugin(rec)
        if "http" in arg.plugins:
            row = row + http_plugin(rec)

        array.append(row)
        if arg.n != 0 and len(array) == arg.n:
            create_output(array, arg.mark, arg.n, header, types)
            array = []

    create_output(array, arg.mark, arg.n, header, types)
    trap.finalize()  # Free allocated TRAP IFCs


if __name__ == "__main__":
    main()
