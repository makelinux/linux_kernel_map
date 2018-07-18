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

import inspect, random, os, sys, collections, subprocess, re

black_list = ['aligned', '__attribute__', 'unlikely', 'typeof',
        'u32',
        'PVOP_CALLEE0', 'PVOP_VCALLEE0', 'PVOP_VCALLEE1', 'trace_hardirqs_off']

level_limit = 7
limit = 10000
n = 0


def print_limited(a):
    print(a)
    global n
    n += 1
    if n > limit:
        print('Reached limit')
        sys.exit(1)


def log(*args, **kwargs):
    print(inspect.stack()[1][3], str(*args).rstrip(), file=sys.stderr, **kwargs)
    pass

def popen(p):
    return subprocess.Popen(p, shell=True, stdout=subprocess.PIPE, encoding="utf-8").stdout

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
            "f=static int fastop(struct x86_emulate_ctxt *ctxt, void (*fop)(struct fastop *))",
            "f=int good(a, bad (*func)(arg))",
            "f=EXPORT_SYMBOL_GPL(bad);",
            "f=bad (*good)()",
            "f=int FNAME(good)(a)",
            "f=TRACE_EVENT(a)",
            "f: a=in bad()"}:
        print(a, '->', extract_referer(a))

def func_referers_git_grep(name):
    res = []
    r = None
    for line in popen(r'git grep --no-index --word-regexp --show-function "^\s.*\b%s"' % (name)):
        # Filter out names in comment afer function, when comment start from ' *'
        # To see the problem try "git grep -p and"
        if re.match(r'.*: \* ', line):
            r = None
        if r and r != name and not r in black_list:
            res.append(r)
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
    res = [l.split()[1] for l in popen(r'cscope -d -L3 "%s"'%(name)) if not l in black_list]
    if not res:
        res = func_referers_git_grep(name)
    return res

def func_referers_all(name):
    return set(func_referers_git_grep(name) + func_referers_cscope(name))

def referers_tree(name, referer=None, printed = None, level = 0):
    if not referer:
        if os.path.isfile('cscope.out'):
            referer = func_referers_cscope
        else:
            print("Using git grep only, recommended to run: cscope -bkR", file=sys.stderr)
            referer = func_referers_git_grep
    if isinstance(referer, str):
        referer = eval(referer)
    if not printed: printed = set()
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
        if a in listed:
            continue
        referers_tree(a, referer, printed, level + 1)
        listed.add(a)
    return ''

def call_tree(node, printed = None, level = 0):
    if not os.path.isfile('cscope.out'):
            print("Please run: cscope -bkR", file=sys.stderr)
            return False
    if printed == None: printed = set()
    if node in printed:
        limit= - 1
        print_limited(level*'\t' + node + ' ^')
        return
    else:
        print_limited(level*'\t' + node)
    printed.add(node)
    if level > level_limit - 2:
        print_limited((level + 1)*'\t' + '...')
        return ''
    local_printed = set()
    for line in popen('cscope -d -L2 "%s"'%(node)):
        I = line.split()[1]
        if I in local_printed or I in black_list: continue;
        local_printed.add(I)
        try:
            call_tree(line.split()[1], printed, level + 1);
        except:
            pass
    return ''

me = os.path.basename(sys.argv[0])

def usage():
    print(me, "referers_tree", "<identifier>")
    print(me, "call_tree", "<identifier>")
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
                ret = eval(sys.argv[1] + '(' + ', '.join("'%s'"%(a) for a in sys.argv[2:]) + ')')
        if type(ret) == type(False) and ret == False:
            sys.exit(os.EX_CONFIG)
        print(ret)
    except KeyboardInterrupt:
        warning("\nInterrupted")

if __name__ == "__main__":
    main()
