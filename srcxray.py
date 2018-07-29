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
import networkx as nx
from networkx.drawing.nx_agraph import *
from networkx.generators.ego import *
from pprint import pprint
import difflib
import glob
from pathlib import *

default_root = 'starts'
black_list = ('aligned __attribute__ unlikely typeof u32'
              'PVOP_CALLEE0 PVOP_VCALLEE0 PVOP_VCALLEE1 if trace_hardirqs_off'
              'i NULL likely unlikely true false test_bit NAPI_GRO_CB clear_bit '
              'atomic_read  preempt_disable preempt_enable  container_of ENOSYS '
              'READ_ONCE u64 u8 _RET_IP_ ret current '
              'AT_FDCWD fdput EBADF file_inode '
              'ssize_t path_put __user '
              'list_empty memcpy size_t loff_t pos d_inode dput copy_to_user  EIO bool out IS_ERR '
              'EPERM rcu_read_lock rcu_read_unlock spin_lock spin_unlock list_for_each_entry kfree '
              'GFP_KERNEL ENOMEM EFAULT ENOENT EAGAIN PTR_ERR PAGE_SHIFT PAGE_SIZE '
              'pgoff_t pte_t pmd_t HPAGE_PMD_NR PageLocked entry swp_entry_t next unlock_page spinlock_t end start '
              ' VM_BUG_ON VM_BUG_ON_PAGE BDI_SHOW max '
              'ssize_t path_put __user '
              'list_del compound_head list_add cond_resched put_page nr_pages min  spin_lock_irqsave IS_ENABLED '
              'EBUSY UL NODE_DATA pr_err memset list size ptl PAGE_MASK pr_info offset addr get_page sprintf '
              'INIT_LIST_HEAD NUMA_NO_NODE spin_unlock_irqrestore  mutex_unlock mutex_lock '
              'page_to_nid page_to_pfn pfn page_zone pfn_to_page'
              'BUG BUG_ON flags WARN_ON_ONCE  ENODEV cpu_to_le16 cpumask_bits '
              'ERR_PTR  ENOTSUPP  EOPNOTSUPP EOPNOTSUPP WARN_ON EINVAL ').split()


level_limit = 8
limit = 100000
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
    s = str(*args).rstrip()
    print(inspect.stack()[1][3],
          s, file=sys.stderr, **kwargs)
    return s


def popen(p):
    return subprocess.check_output(p, shell=True).decode('utf-8').splitlines()


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
                      r'**.\[hc\] **.cpp **.cc **.hh' % (name)):
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


def my_graph(name=None):
    g = nx.DiGraph(name=name)
    # g.graph.update({'node': {'shape': 'none', 'fontsize': 50}})
    # g.graph.update({'rankdir': 'LR', 'nodesep': 0, })
    return g


def reduce_graph(g):
    rm = set()
    for e in g:
        if not g.out_degree(e):
            rm.add(e)
    g.remove_nodes_from(rm)
    return g


def includes(a):
    res = []
    # log(a)
    for a in popen('man -s 2 %s 2> /dev/null |'
                   ' head -n 20 | grep include || true' % (a),
                   shell=True):
        m = re.match('.*<(.*)>', a)
        if m:
            res.append(m.group(1))
    if not res:
        for a in popen('grep -l -r " %s *(" '
                       '/usr/include --include "*.h" '
                       '2> /dev/null || true' % (a)):
            # log(a)
            a = re.sub(r'.*/(bits)', r'\1', a)
            a = re.sub(r'.*/(sys)', r'\1', a)
            a = re.sub(r'/usr/include/(.*)', r'\1', a)
            # log(a)
            res.append(a)
    res = set(res)
    if res and len(res) > 1:
        r = set()
        for f in res:
            # log('grep " %s \+\(" --include "%s" -r /usr/include/'%(a,f))
            # log(os.system(
            # 'grep -w "%s" --include "%s" -r /usr/include/'%(a,f)))
            if 0 != os.system(
                    'grep " %s *(" --include "%s" -r /usr/include/ -q'
                    % (a, os.path.basename(f))):
                r.add(f)
        res = res.difference(r)
    log(res)
    return ','.join(list(res)) if res else 'unexported'


def syscalls():
    sc = my_graph('syscalls')
    inc = 'includes.list'
    if not os.path.isfile(inc):
        os.system('ctags --langmap=c:+.h --c-kinds=+pex -I __THROW '
                  + ' -R -u -f- /usr/include/ | cut -f1,2 > '
                  + inc)
    '''
   if False:
        includes = {}
        with open(inc, 'r') as f:
            for s in f:
                includes[s.split()[0]] = s.split()[1]
        log(includes)
    '''
    scd = 'SYSCALL_DEFINE.list'
    if not os.path.isfile(scd):
        os.system("grep SYSCALL_DEFINE -r --include='*.c' > " + scd)
    with open(scd, 'r') as f:
        v = set('sigsuspend', 'llseek', 'sysfs', 'sync_file_range2', 'ustat', 'bdflush')
        for s in f:
            if any(x in s.lower() for x in ['compat', 'stub']):
                continue
            m = re.match(r'(.*?):.*SYSCALL.*\(([\w]+)', s)
            if m:
                for p in {
                        '^old',
                        '^xnew',
                        r'.*64',
                        r'.*32$',
                        r'.*16$',
                        }:
                    if re.match(p, m.group(2)):
                        m = None
                        break
                if m:
                    syscall = m.group(2)
                    syscall = re.sub('^new', '', syscall)
                    path = m.group(1).split('/')
                    if (m.group(1).startswith('mm/nommu.c')
                            or m.group(1).startswith('arch/x86/ia32')
                            or m.group(1).startswith('arch/')
                            or syscall.startswith('vm86')
                            and not m.group(1).startswith('arch/x86')):
                        continue
                    if syscall in v:
                        continue
                    v.add(syscall)
                    p2 = '/'.join(path[1:])
                    p2 = m.group(1)
                    # if log(difflib.get_close_matches(syscall,v) or ''):
                    #    log(syscall)
                    # log(syscall + ' ' + (includes.get(syscall) or '------'))
                    # man -s 2  timerfd_settime | head -n 20
                    # sc.add_edge('syscalls', path[0] + '/')
                    # sc.add_edge(path[0] + '/', p2)
                    # sc.add_edge(p2, syscall)
                    i = includes(syscall)
                    log(p2 + ' ' + str(i) + ' ' + syscall)
                    sc.add_edge(i, i+' - '+p2)
                    sc.add_edge(i+' - '+p2, syscall)
                    # sc.add_edge(includes(syscall), syscall)
    return sc


# DiGraph
# write_dot to_agraph AGraph
# agwrite
# srcxray.py 'write_dot(syscalls(), "syscalls.dot")'
# srcxray.py "write_dot(import_cflow(),'a.dot')"
# write_graphml
# F=sys_mount; srcxray.py "digraph_print(import_cflow(),['$F'])" > $F.tree
# srcxray.py "leaves(read_dot('a.dot'))"
# srcxray.py "most_used(read_dot('a.dot'))"
# srcxray.py "digraph_print(read_dot('a.dot'))"
# srcxray.py "digraph_print(reduce_graph(reduce_graph(read_dot('a.dot'))))"
# srcxray.py "pprint(most_used(read_dot('a.dot')))"

def cleanup(a):
    dg = read_dot(a)
    print(dg.number_of_edges())
    dg.remove_nodes_from(black_list)
    print(dg.number_of_edges())
    write_dot(dg, a)


def leaves(dg):
    # [x for x in G.nodes() if G.out_degree(x)==0 and G.in_degree(x)==1]
    return {n: dg.in_degree(n) for (n, d) in dg.out_degree if not d}


def most_used(dg, ins=10, outs=10):
    # return {a: b for a, b in sorted(dg.in_degree, key=lambda k: k[1]) if b > 1 and}
    # return [(x, dg.in_degree(x), dg.out_degree(x))
    return [x
            for x in dg.nodes()
            if dg.in_degree(x) >= ins and dg.out_degree(x) >= outs]


def starts(dg):  # roots
    return {n: dg.out_degree(n) for (n, d) in dg.in_degree if not d}


def digraph_tree(dg, starts=None):
    tree = nx.DiGraph()
    def sub(node):
        tree.add_node(node)
        for o in dg.successors(node):
            if o in black_list or tree.has_node(o):
                continue
            tree.add_edge(node,o)
            sub(o)

    printed = set()
    if not starts:
        starts = {}
        for i in [n for (n, d) in dg.in_degree if not d]:
            starts[i] = dg.out_degree(i)
        starts = [a[0] for a in sorted(starts.items(), key=lambda k: k[1], reverse=True)]
    if len(starts) == 1:
        sub(starts[0])
    elif len(starts) > 1:
        for o in starts:
            if o in black_list:
                continue
            tree.add_edge(default_root,o)
            sub(o)
    return tree


def digraph_print(dg, starts=None, sort=False):
    def digraph_print_sub(node=None, printed=None, level=0):
        outs = {_: dg.out_degree(_) for _ in dg.successors(node)}
        if sort:
            outs = {a: b for a, b in sorted(outs.items(), key=lambda k: k[1], reverse=True)}
        if node in printed:
            print_limited(level*'\t' + str(node) + ' ^')
            return
        else:
            s = ' ...' if level > level_limit - 2 and outs else ''
            print_limited(level*'\t' + str(node) + s)
        printed.add(node)
        if level > level_limit - 2:
            return ''
        passed = set()
        for o in outs.keys():
            if o in passed or o in black_list:
                continue
            passed.add(o)
            digraph_print_sub(o, printed, level + 1)

    printed = set()
    if not starts:
        starts = {}
        for i in [n for (n, d) in dg.in_degree if not d]:
            starts[i] = dg.out_degree(i)
        starts = [a[0] for a in sorted(starts.items(), key=lambda k: k[1], reverse=True)]
    if len(starts) > 1:
        print_limited(default_root)
        for s in starts:
            print_limited('\t' + s + ' ->')
    passed = set()
    for o in starts:
        if o in passed or o in black_list:
            continue
        passed.add(o)
        digraph_print_sub(o, printed)


def cflow_preprocess(a):
    with open(a, 'r') as f:
        for s in f:
            # treat struct like function
            s = re.sub(r"^static struct (.*) = ", r"\1()", s)
            s = re.sub(r"^static struct (.*)\[\] = ", r"\1()", s)
            s = re.sub(r"^static const struct (.*)\[\] = ", r"\1()", s)
            s = re.sub(r"^static __initdata int \(\*actions\[\]\)\(void\) = ",
                       "int actions()", s)  # treat struct like function
            s = re.sub(r"^static ", "", s)
            s = re.sub(r"SENSOR_DEVICE_ATTR.*\((\w*),", r"void sensor_dev_attr_\1()(", s)
            s = re.sub(r"COMPAT_SYSCALL_DEFINE[0-9]\((\w*),",
                       r"compat_sys_\1(", s)
            s = re.sub(r"SYSCALL_DEFINE[0-9]\((\w*),", r"sys_\1(", s)
            s = re.sub(r"__setup\(.*,(.*)\)", r"void __setup() {\1();}", s)
            s = re.sub(r"^(\w*)param\(.*,(.*)\)", r"void \1param() {\2();}", s)
            s = re.sub(r"(\w*)initcall\((.*)\)",
                       r"void \1initcall() {\2();}", s)
            s = re.sub(r"^static ", "", s)
            # s = re.sub(r"__read_mostly", "", s)
            s = re.sub(r"^inline ", "", s)
            s = re.sub(r"^const ", "", s)
            s = re.sub(r"^struct (.*) =", r"\1()", s)
            s = re.sub(r"^struct ", "", s)
            # __attribute__
            # for line in sys.stdin:
            sys.stdout.write(s)


cflow_param = {
                "modifier": "__init __inline__ noinline __initdata __randomize_layout __read_mostly asmlinkage "
                " __visible __init __leaf__ __ref",
                "wrapper": "__attribute__ __section__ "
                "TRACE_EVENT MODULE_AUTHOR MODULE_DESCRIPTION MODULE_LICENSE MODULE_LICENSE MODULE_SOFTDEP "
                "__acquires __releases __ATTR"
                # "wrapper": "__setup early_param"
        }

# export CPATH=:include:arch/x86/include:../build/include/:../build/arch/x86/include/generated/:include/uapi
# srcxray.py "'\n'.join(cflow('init/main.c'))"


def cflow(a):
    arg = a
    if not a:
        # arg = "$(find -name '*.[ch]' -o -name '*.cpp' -o -name '*.hh')"
        arg = "*.c *.h *.cpp *.hh "
        arg = " $(cat cscope.files)"
    elif isinstance(a, list):
        pass
    elif os.path.isdir(a):
        pass
    elif os.path.isfile(a):
        pass
    # "--depth=%d " %(level_limit+1) +
    # --debug=1
    cflow = (r"cflow -v "
             # + "-DCONFIG_KALLSYMSZ "
             + "--preprocess='srcxray.py cflow_preprocess' "
             + ''.join([''.join(["--symbol={0}:{1} ".format(w, p)
                       for w in cflow_param[p].split()])
                       for p in cflow_param.keys()])
             + " --include=_sxt --brief --level-indent='0=\t' "
             + a)
    return popen(cflow)


def import_cflow(a=None):
    cf = my_graph()
    stack = list()
    nprev = -1
    for line in cflow(a):
        # --print-level
        m = re.match(r'^([\t]*)([^(^ ^<]+)', str(line))
        if m:
            n = len(m.group(1))
            id = str(m.group(2))
        else:
            raise Exception(line)

        if n <= nprev:
            stack = stack[:n - nprev - 1]
        # print(n, id, stack)
        if id not in black_list:
            if len(stack):
                cf.add_edge(stack[-1], id)
        stack.append(id)
        nprev = n
    return cf


def cflow_linux():
    dirs = 'init fs ipc net fs/ext4 net lib block security crypto mm arch/x86/kernel '.split()
    all = nx.DiGraph()
    for a in dirs:
        for c in glob.glob(os.path.join(a, "*.c")):
                dot = str(Path(c).with_suffix(".dot"))
                if not os.path.isfile(dot):
                    g = import_cflow(c)
                    write_dot(g, dot)
                    print(dot, popen("ctags -x %s | wc -l" % (c))[0], len(set(e[0] for e in g.edges())))
                else:
                    g = read_dot(dot)
                    print(dot)
                all.add_nodes_from(g.nodes())
                all.add_edges_from(g.edges())
    write_dot(all, 'all.dot')


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
        if (ret is not None):
            print(ret)
    except KeyboardInterrupt:
        log("\nInterrupted")


if __name__ == "__main__":
    main()
