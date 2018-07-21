#!/usr/bin/python3
#
#                   srcxray - source code X-ray
#
# Analyzes interconnections between functions and structures in source code.
#
# Uses cscope and git grep --show-function to
# reveal references between identifiers.
#
# 2018 Constantine Shulyupin, const@MakeLinux.com
#

import inspect
import random
import os
import sys
import collections
import subprocess
import re

black_list = ['aligned', '__attribute__', 'unlikely', 'typeof', 'u32',
              'PVOP_CALLEE0', 'PVOP_VCALLEE0', 'PVOP_VCALLEE1', 'if',
              'trace_hardirqs_off']

level_limit = 8
limit = 10000
n = 0


def print_limited(a):
    print(a)
    global n
    n += 1
    if n > limit + 1:
        print('...')
        sys.exit(1)
        # raise(Exception('Reached limit'))


def log(*args, **kwargs):
    print(inspect.stack()[1][3],
          str(*args).rstrip(), file=sys.stderr, **kwargs)
    pass


def popen(p):
    return [a.decode('utf-8') for a in subprocess.check_output(p, shell=True)
            .splitlines()]


def extract_referer(line):
    line = re.sub(r'__ro_after_init', '', line)
    line = re.sub(r'FNAME\((\w+)\)', r'\1', line)
    line = re.sub(r'.*TRACE_EVENT.*', '', line)
    m = re.match(r'^[^\s]+=[^,]*\(\*(\b\w+)\)\s*[\(\[=][^;]*$', line)
    if not m:
        m = re.match(r'^[^\s]+=[^,]*(\b\w+)\s*[\(\[=][^;]*$', line)
    if m:
        return m.group(1)


def extract_referer_test():
    for a in {
            "fs=good2()",
            "f=static int fastop(struct x86_emulate_ctxt *ctxt, "
            + "void (*fop)(struct fastop *))",
            "f=int good(a, bad (*func)(arg))",
            "f=EXPORT_SYMBOL_GPL(bad);",
            "f=bad (*good)()",
            "f=int FNAME(good)(a)",
            "f=TRACE_EVENT(a)",
            "f: a=in bad()"}:
        print(a, '->', extract_referer(a))


def func_referers_git_grep(name):
    res = set()
    r = None
    for line in popen(r'git grep --no-index --word-regexp --show-function '
                      r'"^\s.*\b%s" '
                      '**.\[hc\] **.cpp **.cc **.hh' % (name)):
        # Filter out names in comment afer function,
        # when comment start from ' *'
        # To see the problem try "git grep -p and"
        for p in {
                r'.*:\s+\* .*%s',
                r'.*/\*.*%s',
                r'.*//.*%s',
                r'.*".*\b%s\b.*"'}:
            if re.match(p % (name), line):
                r = None
                break
        if r and r != name and r not in black_list:
            res.add(r)
            r = None
        r = extract_referer(line)
    return res


cscope_warned = False


def func_referers_cscope(name):
    global cscope_warned
    if not os.path.isfile('cscope.out'):
        if not cscope_warned:
            print("Recommended: cscope -bkR", file=sys.stderr)
            cscope_warned = True
        return []
    res = set([l.split()[1] for l in popen(r'cscope -d -L3 "%s"' %
                                       (name)) if l not in black_list])
    if not res:
        res = func_referers_git_grep(name)
    return res


def func_referers_all(name):
    return set(func_referers_git_grep(name) + func_referers_cscope(name))


def referers_tree(name, referer=None, printed=None, level=0):
    if not referer:
        if os.path.isfile('cscope.out'):
            referer = func_referers_cscope
        else:
            print("Using git grep only, recommended to run: cscope -bkR",
                  file=sys.stderr)
            referer = func_referers_git_grep
    if isinstance(referer, str):
        referer = eval(referer)
    if not printed:
        printed = set()
    if name in printed:
        print_limited(level*'\t' + name + ' ^')
        return
    else:
        print_limited(level*'\t' + name)
    printed.add(name)
    if level > level_limit - 2:
        print_limited((level + 1)*'\t' + '...')
        return ''
    listed = set()
    for a in referer(name):
        referers_tree(a, referer, printed, level + 1)
        listed.add(a)
    return ''


def referers_dep(name, referer=None, printed=None, level=0):
    if not referer:
        if os.path.isfile('cscope.out'):
            referer = func_referers_cscope
        else:
            print("Using git grep only, recommended to run: cscope -bkR",
                  file=sys.stderr)
            referer = func_referers_git_grep
    if isinstance(referer, str):
        referer = eval(referer)
    if not printed:
        printed = set()
    if name in printed:
        return
    if level > level_limit - 2:
        return ''
    referers = set(referer(name))
    if referers:
        printed.add(name)
        print(name, end=': ')
        for a in referers:
            print(a, end=' ')
        print()
        for a in referers:
            referers_dep(a, referer, printed, level + 1)
    else:
        pass
        # TODO: print terminal
        # print('...')
    return ''


def call_tree(node, printed=None, level=0):
    if not os.path.isfile('cscope.out'):
        print("Please run: cscope -bkR", file=sys.stderr)
        return False
    if printed is None:
        printed = set()
    if node in printed:
        limit = - 1
        print_limited(level*'\t' + node + ' ^')
        return
    else:
        print_limited(level*'\t' + node)
    printed.add(node)
    if level > level_limit - 2:
        print_limited((level + 1)*'\t' + '...')
        return ''
    local_printed = set()
    for line in popen('cscope -d -L2 "%s"' % (node)):
        a = line.split()[1]
        if a in local_printed or a in black_list:
            continue
        local_printed.add(a)
        # try:
        call_tree(line.split()[1], printed, level + 1)
        # except Exception:
        #    pass
    return ''


def call_dep(node, printed=None, level=0):
    if not os.path.isfile('cscope.out'):
        print("Please run: cscope -bkR", file=sys.stderr)
        return False
    if printed is None:
        printed = set()
    if node in printed:
        return
    calls = set()
    for a in [line.split()[1] for line in
              popen('cscope -d -L2 "%s"' % (node))]:
        if a in black_list:
            continue
        calls.add(a)
    if calls:
        if level < level_limit - 1:
            printed.add(node)
            print(node, end=': ')
            for a in calls:
                print(a, end=' ')
            print()
            for a in calls:
                call_dep(a, printed, level + 1)
        else:
            pass
            # TODO: print terminal
            # print('...')
    return ''


me = os.path.basename(sys.argv[0])


def usage():
    for c in ["referers_tree", "call_tree", "referers_dep", "call_dep"]:
        print(me, c, "<identifier>")
    print("Try this:")
    print("cd linux/init")
    print(me, "referers_tree nfs_root_data")
    print(me, "call_tree start_kernel")
    print(me, "Emergency termination: ^Z, kill %1")


def main():
    try:
        ret = False
        if len(sys.argv) == 1:
            print('Run', me, 'usage')
        else:
            if '(' in sys.argv[1]:
                ret = eval(sys.argv[1])
            else:
                ret = eval(sys.argv[1] + '(' + ', '.join("'%s'" % (a)
                           for a in sys.argv[2:]) + ')')
        if isinstance(ret, bool) and ret is False:
            sys.exit(os.EX_CONFIG)
        print(ret)
    except KeyboardInterrupt:
        warning("\nInterrupted")


if __name__ == "__main__":
    main()
