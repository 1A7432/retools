"""The evaluator: a tree-walking interpreter for a small Python subset.

Safety rests on three facts, each enforced here rather than by Python:
  1. The only syntax that runs is the allow-listed node types below; anything
     else is refused before evaluation starts.
  2. Values are only int, bool, str, bytes, list, tuple, dict, None and range.
     Built-in functions and methods are looked up by name in fixed tables and
     their results are checked to be of those types again. There is no way to
     name or obtain a Python object, function, type or module as a value.
  3. Attribute syntax is only accepted as a method call whose (type, name)
     pair is in the method table; names starting with "_" are refused.
Every operation that can grow a value is checked against the limits before
it runs, and a step counter bounds the total work.
"""

from __future__ import annotations

import ast
import difflib
import io
import tokenize
import warnings

from . import limits as L
from .errors import CalcError, LimitError, short
from .limits import check_value, need_bits, need_len, walk

_CONT = (list, tuple, dict)
# built-ins and methods that compare or hash the elements of their arguments
COMPARING = {"sorted", "min", "max", "dict", "list.sort", "list.index", "list.count",
             "tuple.index", "tuple.count", "dict.get", "dict.pop", "dict.setdefault", "dict.update"}

NoneType = type(None)


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


class _Return(Exception):
    def __init__(self, value):
        self.value = value


_OPS = {ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow, ast.LShift, ast.RShift,
        ast.BitOr, ast.BitXor, ast.BitAnd}
_UNARY = {ast.USub, ast.UAdd, ast.Invert, ast.Not}
_CMP = {ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn, ast.Is, ast.IsNot}
_STMTS = {ast.Expr, ast.Assign, ast.AugAssign, ast.For, ast.While, ast.If, ast.Break, ast.Continue,
          ast.Pass, ast.FunctionDef, ast.Return, ast.Assert}
_EXPRS = {ast.Constant, ast.Name, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp,
          ast.Subscript, ast.Slice, ast.List, ast.Tuple, ast.Dict, ast.ListComp, ast.GeneratorExp,
          ast.DictComp, ast.Call, ast.Attribute}
_OTHER = {ast.Module, ast.Load, ast.Store, ast.comprehension, ast.keyword, ast.arguments, ast.arg,
          ast.And, ast.Or}
ALLOWED = _OPS | _UNARY | _CMP | _STMTS | _EXPRS | _OTHER

_REFUSED = {
    "Import": "import is not available; every function there is is already in the table",
    "ImportFrom": "import is not available; every function there is is already in the table",
    "Lambda": "lambda is not supported; use a top-level def",
    "JoinedStr": "f-strings are not supported; use print(a, b), hex(x) or hexstr(b)",
    "FormattedValue": "f-strings are not supported; use print(a, b), hex(x) or hexstr(b)",
    "ClassDef": "classes are not supported",
    "AsyncFunctionDef": "async is not supported",
    "With": "with is not supported", "AsyncWith": "with is not supported",
    "Try": "try/except is not supported; errors end the run with a message",
    "TryStar": "try/except is not supported",
    "Raise": "raise is not supported; use assert",
    "Global": "global is not supported; functions read top-level names but assign locally",
    "Nonlocal": "nonlocal is not supported",
    "Delete": "del is not supported; reassign instead",
    "Set": "sets are not supported; use a list or dict", "SetComp": "sets are not supported",
    "Starred": "*unpacking is not supported",
    "NamedExpr": ":= is not supported; assign on its own line",
    "Await": "await is not supported", "Yield": "generators are not supported",
    "YieldFrom": "generators are not supported", "Match": "match is not supported; use if/elif",
    "AnnAssign": "annotations are not supported; write x = value",
    "MatMult": "@ is not an operator here",
    "Div": "/ is float division and floats are not supported; use // (floor) or divmod(a, b)",
    "TypeAlias": "type aliases are not supported",
}


def _type_name(v):
    t = type(v)
    return {NoneType: "None"}.get(t, t.__name__)


class Frame:
    __slots__ = ("vars", "is_global", "fname")

    def __init__(self, vars, is_global, fname=None):
        self.vars, self.is_global, self.fname = vars, is_global, fname


class UserFunc:
    __slots__ = ("node", "defaults", "params")

    def __init__(self, node, defaults):
        self.node = node
        self.params = [a.arg for a in node.args.args]
        self.defaults = defaults


# ---------------------------------------------------------------- validation

def parse(code):
    if not isinstance(code, str):
        raise CalcError("code must be a string")
    if len(code) > L.MAX_CODE:
        raise LimitError("code_length", "%d characters of code (limit %d)" % (len(code), L.MAX_CODE),
                         "split the work into several calls")
    if "\x00" in code:
        raise CalcError("code contains a NUL character")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")          # SyntaxWarnings would go to stderr
            tree = ast.parse(code, mode="exec")
    except SyntaxError as exc:
        raise CalcError("syntax error: %s" % exc.msg, "this is Python syntax (a subset)", exc.lineno)
    except (RecursionError, MemoryError):
        raise LimitError("nesting", "the code is nested too deeply to parse")
    except ValueError as exc:     # e.g. an over-long decimal literal
        raise CalcError("cannot parse: %s" % exc, "write large numbers in hex")
    _check_identifiers(code)
    _check_depth(tree)
    _Validator().visit_module(tree)
    return tree


def _check_identifiers(code):
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            if tok.type == tokenize.NAME and not tok.string.isascii():
                raise CalcError("identifier %r contains non-ASCII characters" % tok.string,
                                "use plain ASCII names (look-alike letters are refused)", tok.start[0])
    except (tokenize.TokenError, SyntaxError):
        pass   # ast.parse already accepted the code; nothing more to learn here


def _check_depth(tree):
    stack = [(tree, 1)]
    while stack:
        node, d = stack.pop()
        if d > L.MAX_AST_DEPTH:
            raise LimitError("nesting", "the code is nested more than %d levels deep" % L.MAX_AST_DEPTH,
                             "split long expressions into several assignments")
        for child in ast.iter_child_nodes(node):
            stack.append((child, d + 1))


class _Validator:
    def __init__(self):
        from .table import METHOD_NAMES, STATICS
        self.method_names = METHOD_NAMES
        self.statics = STATICS
        self.in_func = False
        self.loops = 0

    def fail(self, node, msg, hint=""):
        raise CalcError(msg, hint, getattr(node, "lineno", None))

    def visit_module(self, tree):
        for st in tree.body:
            self.visit(st, top=True)

    def name(self, node, ident):
        if ident.startswith("_"):
            self.fail(node, "names starting with '_' are not allowed: %s" % ident)

    def visit(self, node, top=False, call_func=False):
        t = type(node)
        if t not in ALLOWED:
            nm = t.__name__
            self.fail(node, _REFUSED.get(nm, "%s is not supported" % nm),
                      "see the README for the supported language")
        if t is ast.Constant:
            v = node.value
            if type(v) not in (int, bool, str, bytes, NoneType):
                self.fail(node, "%s literals are not supported" % type(v).__name__,
                          "only integers, bytes, strings, True/False/None")
            check_value(v)
            return
        if t is ast.Name:
            self.name(node, node.id)
            return
        if t is ast.Slice:
            self.fail(node, "a slice is only allowed directly inside [...], e.g. b[1:4]",
                      "slices cannot be stored or combined in a tuple")
        if t is ast.Subscript:
            self.visit(node.value)
            self.subscript_key(node.slice)
            return
        if t is ast.Attribute:
            self.name(node, node.attr)
            if not call_func:
                self.fail(node, "attribute access is only allowed to call a method, e.g. b.hex()",
                          "there are no fields to read")
            if node.attr not in self.method_names and not any(
                    node.attr in names for names in self.statics.values()):
                self.fail(node, "there is no method .%s" % node.attr,
                          "methods: " + ", ".join(sorted(self.method_names)))
            self.visit(node.value)
            return
        if t is ast.FunctionDef:
            self.funcdef(node, top)
            return
        if t in (ast.For, ast.While):
            if t is ast.For:
                self.target(node.target)
                self.visit(node.iter)
            else:
                self.visit(node.test)
            self.loops += 1
            for st in node.body:
                self.visit(st)
            self.loops -= 1
            for st in node.orelse:
                self.visit(st)
            return
        if t in (ast.Break, ast.Continue):
            if not self.loops:
                self.fail(node, "%s outside a loop" % t.__name__.lower())
            return
        if t is ast.Return:
            if not self.in_func:
                self.fail(node, "return outside a def", "the value of the last line is the result")
            if node.value is not None:
                self.visit(node.value)
            return
        if t in (ast.Assign, ast.AugAssign):
            for tg in (node.targets if t is ast.Assign else [node.target]):
                self.target(tg, aug=t is ast.AugAssign)
            self.visit(node.value)
            if t is ast.AugAssign:
                self.visit(node.op)
            return
        if t is ast.Call:
            self.visit(node.func, call_func=True)
            if type(node.func) not in (ast.Name, ast.Attribute):
                self.fail(node, "only named functions and methods can be called")
            for a in node.args:
                self.visit(a)
            for kw in node.keywords:
                if kw.arg is None:
                    self.fail(node, "**kwargs is not supported")
                self.name(kw, kw.arg)
                self.visit(kw.value)
            return
        if t is ast.Dict:
            if any(k is None for k in node.keys):
                self.fail(node, "**unpacking in a dict is not supported")
        if t is ast.comprehension:
            if node.is_async:
                self.fail(node, "async comprehensions are not supported")
            self.target(node.target)
            self.visit(node.iter)
            for c in node.ifs:
                self.visit(c)
            return
        for child in ast.iter_child_nodes(node):
            self.visit(child)

    def target(self, node, aug=False):
        t = type(node)
        if t is ast.Name:
            self.name(node, node.id)
        elif t in (ast.Tuple, ast.List) and not aug:
            for e in node.elts:
                self.target(e)
        elif t is ast.Subscript:
            self.visit(node.value)
            self.subscript_key(node.slice)
        else:
            self.fail(node, "cannot assign to this", "assign to a name, a tuple of names, or x[i]")

    def subscript_key(self, node):
        if type(node) is ast.Slice:
            for part in (node.lower, node.upper, node.step):
                if part is not None:
                    self.visit(part)
        else:
            self.visit(node)

    def funcdef(self, node, top):
        self.name(node, node.name)
        if not top or self.in_func:
            self.fail(node, "def is only allowed at the top level (no nested functions)")
        a = node.args
        if node.decorator_list or a.vararg or a.kwarg or a.kwonlyargs or a.posonlyargs or node.returns \
                or getattr(node, "type_params", None):
            self.fail(node, "def supports plain positional parameters (with optional defaults) only")
        for arg in a.args:
            self.name(arg, arg.arg)
            if arg.annotation is not None:
                self.fail(arg, "annotations are not supported")
        for d in a.defaults:
            self.visit(d)
        self.in_func, loops = True, self.loops
        self.loops = 0
        for st in node.body:
            self.visit(st)
        self.in_func, self.loops = False, loops


# --------------------------------------------------------------- evaluation

class Interp:
    def __init__(self, budget, functions, methods, statics, render_text):
        self.budget = budget
        self.functions = functions        # name -> callable(*values, **values)
        self.methods = methods            # (type, name) -> callable(obj, *values, **values)
        self.statics = statics            # "int" -> {"from_bytes": callable}
        self.render_text = render_text
        self.globals = {}
        self.funcs = {}
        self.active = []
        self.printed = []
        self.print_dropped = 0
        self.lineno = None
        self.has_result = False
        self.result = None
        self._stmt = {
            ast.Expr: self.s_expr, ast.Assign: self.s_assign, ast.AugAssign: self.s_augassign,
            ast.For: self.s_for, ast.While: self.s_while, ast.If: self.s_if,
            ast.Break: self.s_break, ast.Continue: self.s_continue, ast.Pass: lambda n, f: None,
            ast.FunctionDef: self.s_def, ast.Return: self.s_return, ast.Assert: self.s_assert,
        }
        self._expr = {
            ast.Constant: lambda n, f: n.value, ast.Name: self.e_name, ast.BinOp: self.e_binop,
            ast.UnaryOp: self.e_unary, ast.BoolOp: self.e_boolop, ast.Compare: self.e_compare,
            ast.IfExp: self.e_ifexp, ast.Subscript: self.e_subscript, ast.List: self.e_list,
            ast.Tuple: self.e_tuple, ast.Dict: self.e_dict, ast.ListComp: self.e_listcomp,
            ast.GeneratorExp: self.e_listcomp, ast.DictComp: self.e_dictcomp, ast.Call: self.e_call,
            ast.Slice: self.e_slice,
        }

    # -- driver

    def run(self, tree):
        frame = Frame(self.globals, True)
        body = tree.body
        for i, st in enumerate(body):
            last = i == len(body) - 1
            if last and type(st) is ast.Expr:
                self.lineno = st.lineno
                self.result = self.eval(st.value, frame)
                self.has_result = True
            else:
                self.exec(st, frame)

    def exec(self, node, frame):
        self.budget.step()
        self.lineno = node.lineno
        self._stmt[type(node)](node, frame)

    def exec_body(self, body, frame):
        for st in body:
            self.exec(st, frame)

    def eval(self, node, frame):
        self.budget.step()
        ln = getattr(node, "lineno", None)
        if ln is not None:
            self.lineno = ln
        return self._expr[type(node)](node, frame)

    # -- statements

    def s_expr(self, node, frame):
        self.eval(node.value, frame)

    def s_assign(self, node, frame):
        v = self.eval(node.value, frame)
        for tg in node.targets:
            self.assign(tg, v, frame)

    def assign(self, tg, v, frame):
        t = type(tg)
        if t is ast.Name:
            frame.vars[tg.id] = v
        elif t in (ast.Tuple, ast.List):
            if type(v) not in (list, tuple, range, bytes, str):
                raise CalcError("cannot unpack a %s into %d names" % (_type_name(v), len(tg.elts)))
            if len(v) != len(tg.elts):
                raise CalcError("cannot unpack %d values into %d names" % (len(v), len(tg.elts)))
            for sub, item in zip(tg.elts, v):
                self.assign(sub, item, frame)
        else:
            obj = self.eval(tg.value, frame)
            key = self.eval(tg.slice, frame)
            self.setitem(obj, key, v)

    def setitem(self, obj, key, v):
        to = type(obj)
        if to is list:
            if type(key) is slice:
                if type(v) not in (list, tuple, range, bytes):
                    raise CalcError("a list slice can only be assigned a sequence")
                cur = len(range(*key.indices(len(obj))))
                need_len(len(obj) - cur + len(v), "the list")
                self.budget.step(len(v) >> 4)
                obj[key] = list(v)
            else:
                obj[self.index(key)] = v
        elif to is dict:
            self.guard(key)
            if key not in obj:
                need_len(len(obj) + 1, "the dict")
            obj[key] = v
        elif to in (bytes, str, tuple):
            raise CalcError("a %s cannot be changed in place" % to.__name__,
                            "use a list (list(b)), change it, then bytes(lst); or build a new value with slices")
        else:
            raise CalcError("cannot assign into a %s" % _type_name(obj))

    @staticmethod
    def index(key):
        if type(key) not in (int, bool):
            raise CalcError("list indices must be integers, not %s" % _type_name(key))
        return key

    def s_augassign(self, node, frame):
        tg = node.target
        rhs = self.eval(node.value, frame)
        if type(tg) is ast.Name:
            cur = self.lookup(tg.id, frame)
            frame.vars[tg.id] = self.binop(node.op, cur, rhs)
        else:
            obj = self.eval(tg.value, frame)
            key = self.eval(tg.slice, frame)
            cur = self.getitem(obj, key)
            self.setitem(obj, key, self.binop(node.op, cur, rhs))

    def iterable(self, v):
        t = type(v)
        if t in (list, tuple, range, bytes, str):
            return v
        if t is dict:
            return list(v)
        raise CalcError("cannot loop over a %s" % _type_name(v))

    def s_for(self, node, frame):
        seq = self.iterable(self.eval(node.iter, frame))
        broke = False
        for item in seq:
            self.budget.iterate()
            self.assign(node.target, item, frame)
            try:
                self.exec_body(node.body, frame)
            except _Break:
                broke = True
                break
            except _Continue:
                continue
        if not broke:
            self.exec_body(node.orelse, frame)

    def s_while(self, node, frame):
        broke = False
        while self.truth(self.eval(node.test, frame)):
            self.budget.iterate()
            try:
                self.exec_body(node.body, frame)
            except _Break:
                broke = True
                break
            except _Continue:
                continue
        if not broke:
            self.exec_body(node.orelse, frame)

    def s_if(self, node, frame):
        if self.truth(self.eval(node.test, frame)):
            self.exec_body(node.body, frame)
        else:
            self.exec_body(node.orelse, frame)

    def s_break(self, node, frame):
        raise _Break()

    def s_continue(self, node, frame):
        raise _Continue()

    def s_return(self, node, frame):
        raise _Return(None if node.value is None else self.eval(node.value, frame))

    def s_def(self, node, frame):
        if node.name in self.globals:
            raise CalcError("%s is already a variable; pick another name for the def" % node.name)
        self.funcs[node.name] = UserFunc(node, [self.eval(d, frame) for d in node.args.defaults])

    def s_assert(self, node, frame):
        t = node.test
        if type(t) is ast.Compare and len(t.ops) == 1:
            left = self.eval(t.left, frame)
            right = self.eval(t.comparators[0], frame)
            ok = self.compare(t.ops[0], left, right)
            detail = " (left: %s, right: %s)" % (self.render_text(left), self.render_text(right))
        else:
            ok = self.truth(self.eval(t, frame))
            detail = ""
        if not ok:
            msg = ""
            if node.msg is not None:
                m = self.eval(node.msg, frame)
                msg = ": " + (m if isinstance(m, str) else self.render_text(m))
            raise CalcError("assertion failed%s%s" % (msg, detail), "", node.lineno)

    # -- expressions

    @staticmethod
    def truth(v):
        return bool(v)

    def lookup(self, name, frame):
        if name in frame.vars:
            return frame.vars[name]
        if not frame.is_global and name in self.globals:
            return self.globals[name]
        if name in self.funcs or name in self.functions or name in self.statics:
            raise CalcError("%s is a function; call it, e.g. %s(...)" % (name, name),
                            "functions are not values: they cannot be stored or passed")
        raise CalcError("name %r is not defined" % name, self._suggest(name, frame, values=True))

    def _suggest(self, name, frame, values=False):
        pool = set(self.functions) | set(self.funcs)
        if values:
            pool |= set(frame.vars) | set(self.globals)
        close = difflib.get_close_matches(name, sorted(pool), n=5, cutoff=0.6)
        if not close:
            low = name.lower()
            close = sorted(n for n in pool if low in n.lower() or n.lower() in low)[:5]
        return ("did you mean: %s?" % ", ".join(close)) if close else \
            "see the README for the function list"

    def e_name(self, node, frame):
        return self.lookup(node.id, frame)

    def e_unary(self, node, frame):
        v = self.eval(node.operand, frame)
        op = type(node.op)
        if op is ast.Not:
            return not self.truth(v)
        if type(v) not in (int, bool):
            raise CalcError("unary %s needs an integer, got %s" % (
                {ast.USub: "-", ast.UAdd: "+", ast.Invert: "~"}[op], _type_name(v)))
        if op is ast.USub:
            return -v
        if op is ast.UAdd:
            return +v
        return ~v

    def e_boolop(self, node, frame):
        is_and = type(node.op) is ast.And
        v = None
        for sub in node.values:
            v = self.eval(sub, frame)
            if self.truth(v) != is_and:
                return v
        return v

    def e_compare(self, node, frame):
        left = self.eval(node.left, frame)
        for op, comp in zip(node.ops, node.comparators):
            right = self.eval(comp, frame)
            if not self.compare(op, left, right):
                return False
            left = right
        return True

    def guard(self, *vals):
        n = 0
        for v in vals:
            if type(v) in _CONT:
                n += walk(v)
        if n:
            self.budget.step(n >> 4)

    def compare(self, op, a, b):
        t = type(op)
        if t in (ast.In, ast.NotIn) and type(b) is range:
            # CPython scans a range linearly when the left side is not an int
            r = type(a) in (int, bool) and a in b
            return r if t is ast.In else not r
        if t in (ast.In, ast.NotIn):
            # one hash plus a few comparisons for a dict; one comparison per
            # element for a list, each bounded by the size of the left side
            w = walk(a)
            if type(b) in (list, tuple) and w and len(b) * (w + 1) > L.MAX_WALK:
                raise LimitError("structure", "'in' would visit about %d elements" % (len(b) * (w + 1)))
            self.budget.step((w + (len(b) if type(b) in (list, tuple) else 0)) >> 4)
        elif type(a) in _CONT or type(b) in _CONT:
            self.guard(a, b)
        if t in (ast.In, ast.NotIn):
            if type(b) not in (list, tuple, range, bytes, str, dict):
                raise CalcError("'in' needs a sequence or dict on the right, got %s" % _type_name(b))
            if type(b) is bytes and type(a) not in (bytes, int, bool):
                raise CalcError("'in' on bytes needs bytes or a byte value on the left")
            if type(b) is str and type(a) is not str:
                raise CalcError("'in' on a string needs a string on the left")
            r = a in b
            return r if t is ast.In else not r
        if t is ast.Is:
            return a is b if (a is None or b is None or type(a) is bool) else a == b
        if t is ast.IsNot:
            return a is not b if (a is None or b is None or type(a) is bool) else a != b
        if t is ast.Eq:
            return a == b
        if t is ast.NotEq:
            return a != b
        try:
            if t is ast.Lt:
                return a < b
            if t is ast.LtE:
                return a <= b
            if t is ast.Gt:
                return a > b
            return a >= b
        except TypeError:
            raise CalcError("cannot order %s and %s" % (_type_name(a), _type_name(b)))

    def e_ifexp(self, node, frame):
        return self.eval(node.body if self.truth(self.eval(node.test, frame)) else node.orelse, frame)

    def e_slice(self, node, frame):
        parts = []
        for p in (node.lower, node.upper, node.step):
            v = None if p is None else self.eval(p, frame)
            if v is not None and type(v) not in (int, bool):
                raise CalcError("slice bounds must be integers, not %s" % _type_name(v))
            parts.append(v)
        if parts[2] == 0:
            raise CalcError("slice step cannot be zero")
        return slice(*parts)

    def e_subscript(self, node, frame):
        obj = self.eval(node.value, frame)
        key = self.eval(node.slice, frame)
        return self.getitem(obj, key)

    def getitem(self, obj, key):
        to = type(obj)
        if to is dict:
            self.guard(key)
            try:
                return obj[key]
            except KeyError:
                raise CalcError("key %s is not in the dict" % self.render_text(key),
                                "use d.get(key, default) when it may be missing")
            except TypeError:
                raise CalcError("a %s cannot be a dict key" % _type_name(key))
        if to not in (list, tuple, bytes, str, range):
            raise CalcError("a %s cannot be indexed" % _type_name(obj))
        if type(key) is slice:
            return obj[key]
        self.index(key)
        try:
            return obj[key]
        except IndexError:
            raise CalcError("index %s is out of range for a %s of length %d" % (short(key), to.__name__, len(obj)))

    def e_list(self, node, frame):
        return [self.eval(e, frame) for e in node.elts]

    def e_tuple(self, node, frame):
        return tuple(self.eval(e, frame) for e in node.elts)

    def e_dict(self, node, frame):
        out = {}
        for k, v in zip(node.keys, node.values):
            key = self.eval(k, frame)
            self.guard(key)
            val = self.eval(v, frame)
            try:
                out[key] = val
            except TypeError:
                raise CalcError("a %s cannot be a dict key" % _type_name(key))
        return out

    def _comp(self, gens, frame, emit):
        """Run comprehension generators in a scope layered on top of `frame`."""
        # globals stay reachable through lookup() when frame is a function frame
        scope = Frame(dict(frame.vars), frame.is_global, frame.fname)

        def level(i):
            if i == len(gens):
                emit(scope)
                return
            g = gens[i]
            for item in self.iterable(self.eval(g.iter, scope)):
                self.budget.iterate()
                self.assign(g.target, item, scope)
                if all(self.truth(self.eval(c, scope)) for c in g.ifs):
                    level(i + 1)

        level(0)

    def e_listcomp(self, node, frame):
        out = []

        def emit(scope):
            need_len(len(out) + 1, "the list")
            out.append(self.eval(node.elt, scope))

        self._comp(node.generators, frame, emit)
        return out

    def e_dictcomp(self, node, frame):
        out = {}

        def emit(scope):
            k = self.eval(node.key, scope)
            self.guard(k)
            v = self.eval(node.value, scope)
            try:
                if k not in out:
                    need_len(len(out) + 1, "the dict")
                out[k] = v
            except TypeError:
                raise CalcError("a %s cannot be a dict key" % _type_name(k),
                                "dict keys must be int, str, bytes, bool, None or tuples of those")

        self._comp(node.generators, frame, emit)
        return out

    # -- operators

    def binop(self, op, a, b):
        t = type(op)
        ta, tb = type(a), type(b)
        ints = ta in (int, bool) and tb in (int, bool)
        if t is ast.Add:
            if not ints:
                if ta is tb and ta in (bytes, str, list, tuple):
                    need_len(len(a) + len(b))
                else:
                    raise CalcError("cannot add %s and %s" % (_type_name(a), _type_name(b)),
                                    "bytes + bytes, str + str, list + list or int + int; convert first")
                self.budget.step((len(a) + len(b)) >> 4)
            return check_value(a + b)
        if t is ast.Mult:
            if ints:
                need_bits(a.bit_length() + b.bit_length() - 1, "the product")
            elif ta in (bytes, str, list, tuple) and tb in (int, bool):
                need_len(len(a) * max(b, 0))
                self.budget.step((len(a) * max(b, 0)) >> 4)
            elif tb in (bytes, str, list, tuple) and ta in (int, bool):
                need_len(len(b) * max(a, 0))
                self.budget.step((len(b) * max(a, 0)) >> 4)
            else:
                raise CalcError("cannot multiply %s and %s" % (_type_name(a), _type_name(b)))
            return check_value(a * b)
        if not ints:
            if t is ast.Mod and ta in (str, bytes):
                raise CalcError("%-formatting is not available", "use hex(x), hexstr(b) or print(a, b)")
            if t is ast.BitOr and ta is dict and tb is dict:
                need_len(len(a) + len(b))
                self.budget.step((len(a) + len(b)) >> 4)
                return a | b
            sym = {ast.Sub: "-", ast.FloorDiv: "//", ast.Mod: "%", ast.Pow: "**", ast.LShift: "<<",
                   ast.RShift: ">>", ast.BitOr: "|", ast.BitXor: "^", ast.BitAnd: "&"}[t]
            hint = "for byte strings use xor(a, b)" if sym == "^" and bytes in (ta, tb) else \
                "operands must be integers"
            raise CalcError("unsupported operand types for %s: %s and %s" % (sym, _type_name(a), _type_name(b)),
                            hint)
        if t is ast.Sub or t is ast.BitAnd or t is ast.BitOr or t is ast.BitXor:
            r = {ast.Sub: lambda: a - b, ast.BitAnd: lambda: a & b, ast.BitOr: lambda: a | b,
                 ast.BitXor: lambda: a ^ b}[t]()
            return check_value(r)
        if t is ast.FloorDiv or t is ast.Mod:
            if b == 0:
                raise CalcError("division by zero")
            return a // b if t is ast.FloorDiv else a % b
        if t is ast.Pow:
            if b < 0:
                raise CalcError("negative exponent gives a fraction",
                                "for a modular inverse use pow(b, -1, m) or inverse(b, m)")
            need_bits(L.pow_bits(a, b), "the power")
            return check_value(a ** b)
        if t is ast.LShift:
            if b < 0:
                raise CalcError("negative shift count")
            if a:
                need_bits(a.bit_length() + b, "the shift")
            return check_value(a << b) if a else 0
        if t is ast.RShift:
            if b < 0:
                raise CalcError("negative shift count")
            return a >> b if b < L.MAX_INT_BITS + 1 else (-1 if a < 0 else 0)
        raise CalcError("unsupported operator")

    def e_binop(self, node, frame):
        a = self.eval(node.left, frame)
        b = self.eval(node.right, frame)
        return self.binop(node.op, a, b)

    # -- calls

    def e_call(self, node, frame):
        fn = node.func
        if type(fn) is ast.Name:
            name = fn.id
            shadow = name in frame.vars or (not frame.is_global and name in self.globals)
            if shadow:
                v = self.lookup(name, frame)
                hint = ("the variable hides the built-in %s(); rename the variable" % name) \
                    if name in self.functions or name in self.funcs else ""
                raise CalcError("%s is a variable (%s) here, not a function" % (name, _type_name(v)), hint)
            args, kwargs = self.call_args(node, frame)
            if name == "print":
                return self.do_print(args, kwargs)
            if name in self.funcs:
                return self.call_user(name, args, kwargs)
            if name in self.functions:
                return self.call_builtin(name, self.functions[name], args, kwargs)
            raise CalcError("unknown function %r" % name, self._suggest(name, frame))
        # method call
        base = fn.value
        attr = fn.attr
        if type(base) is ast.Name and base.id in self.statics and base.id not in frame.vars \
                and base.id not in self.globals:
            table = self.statics[base.id]
            if attr not in table:
                raise CalcError("%s.%s does not exist" % (base.id, attr),
                                "available: " + ", ".join("%s.%s" % (base.id, a) for a in sorted(table)))
            args, kwargs = self.call_args(node, frame)
            return self.call_builtin("%s.%s" % (base.id, attr), table[attr], args, kwargs)
        obj = self.eval(base, frame)
        to = int if type(obj) is bool else type(obj)
        m = self.methods.get((to, attr))
        if m is None:
            have = sorted(n for (tt, n) in self.methods if tt is to)
            raise CalcError("a %s has no method .%s" % (_type_name(obj), attr),
                            ("methods of %s: %s" % (_type_name(obj), ", ".join(have))) if have
                            else "a %s has no methods" % _type_name(obj))
        args, kwargs = self.call_args(node, frame)
        return self.call_builtin("%s.%s" % (_type_name(obj), attr), m, [obj] + args, kwargs, method=True)

    def call_args(self, node, frame):
        args = [self.eval(a, frame) for a in node.args]
        kwargs = {}
        for kw in node.keywords:
            if kw.arg in kwargs:
                raise CalcError("keyword %s given twice" % kw.arg)
            kwargs[kw.arg] = self.eval(kw.value, frame)
        return args, kwargs

    def call_builtin(self, name, f, args, kwargs, method=False):
        cost = 0
        for v in args:
            tv = type(v)
            if tv in (bytes, str, list, tuple, dict):
                cost += len(v) >> 4
            elif tv is int:
                cost += v.bit_length() >> 8
        self.budget.step(1 + cost)
        if name in COMPARING:
            self.guard(*args, *kwargs.values())
        try:
            r = f(*args, **kwargs)
        except CalcError:
            raise
        except TypeError as exc:
            from .table import signature
            raise CalcError("%s: %s" % (name, str(exc)[:200]), "usage: " + signature(name))
        except KeyError as exc:
            key = exc.args[0] if exc.args else None
            raise CalcError("%s: key %s not found" % (name, short(key)))
        except (ValueError, OverflowError, IndexError, ZeroDivisionError) as exc:
            raise CalcError("%s: %s" % (name, str(exc)[:200] or type(exc).__name__))
        if type(r) in (bytes, str, list, tuple, dict):
            self.budget.step(len(r) >> 4)       # allocation volume, so memory checks keep up
        return self.clean(r, name)

    def clean(self, v, name, depth=0, seen=None):
        """Make sure a built-in returned only allowed value types, within limits.
        Containers are checked two levels deep, each object once; anything
        deeper was a language value already (built-ins only nest shallowly)."""
        t = type(v)
        if t in (int, bool, str, bytes, NoneType, range):
            return check_value(v)
        if t is bytearray:
            return check_value(bytes(v))
        if t in (list, tuple, dict):
            check_value(v)
            seen = set() if seen is None else seen
            if depth < 2 and id(v) not in seen:
                seen.add(id(v))
                for x in (v if t is not dict else [y for kv in v.items() for y in kv]):
                    self.clean(x, name, depth + 1, seen)
            return v
        raise CalcError("internal error: %s returned a %s" % (name, t.__name__), "please report this")

    def call_user(self, name, args, kwargs):
        uf = self.funcs[name]
        if name in self.active:
            raise LimitError("recursion", "%s calls itself (through %s); recursion is not supported"
                             % (name, " -> ".join(self.active + [name])), "rewrite it as a loop")
        if len(self.active) >= L.MAX_CALL_DEPTH:
            raise LimitError("call_depth", "more than %d nested function calls" % L.MAX_CALL_DEPTH)
        params = uf.params
        if len(args) > len(params):
            raise CalcError("%s() takes %d arguments, got %d" % (name, len(params), len(args)))
        local = dict(zip(params, args))
        for k, v in kwargs.items():
            if k not in params:
                raise CalcError("%s() has no parameter %r" % (name, k), "parameters: " + ", ".join(params))
            if k in local:
                raise CalcError("%s() got two values for %r" % (name, k))
            local[k] = v
        nd = len(uf.defaults)
        for i, p in enumerate(params):
            if p not in local:
                j = i - (len(params) - nd)
                if j < 0:
                    raise CalcError("%s() is missing the argument %r" % (name, p))
                local[p] = uf.defaults[j]
        frame = Frame(local, False, name)
        self.active.append(name)
        line = self.lineno
        try:
            self.exec_body(uf.node.body, frame)
            ret = None
        except _Return as r:
            ret = r.value
        finally:
            self.active.pop()
        self.lineno = line
        return ret

    def do_print(self, args, kwargs):
        if kwargs:
            raise CalcError("print takes no keyword arguments here")
        if len(self.printed) >= L.MAX_PRINT:
            self.print_dropped += 1
            return None
        self.printed.append(" ".join(a if isinstance(a, str) else self.render_text(a) for a in args)[:2000])
        return None
