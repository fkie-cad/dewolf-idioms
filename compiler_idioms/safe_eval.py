import re


def safe_eval(expression, values):
    """
    Implements a somehow safer way to use eval (see https://realpython.com/python-eval-function/) for our needs
    """
    # ensure that only names from given dict are used
    # also ensure only const_X and reg_X variable names are used
    allowed_regex = r"(reg_\d+)|(const_\d+)"
    code = compile(expression, "<string>", "eval")
    for name in code.co_names:
        if name not in values or not re.match(allowed_regex, name):
            raise NameError(f"Use of {name} in compiler idiom pattern not allowed")
    # override builtins to prevent import
    return eval(code, {"__builtins__": {}}, values)
