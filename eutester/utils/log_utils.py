__author__ = 'clarkmatthew'

import os
import sys
# Force ansi escape sequences (markup) in output.
# This can also be set as an env var
_EUTESTER_FORCE_ANSI_ESCAPE = False
# Allow ansi color codes outside the standard range. For example some systems support
# a high intensity color range from 90-109.
# This can also be set as an env var
_EUTESTER_NON_STANDARD_ANSI_SUPPORT = False

def markup(text, markups=[1], resetvalue="\033[0m", force=None, allow_nonstandard=None):
    """
    Convenience method for using ansi markup. Attempts to check if terminal supports
    ansi escape sequences for text markups. If so will return a marked up version of the
    text supplied using the markups provided.
    Some example markeups: 1 = bold, 4 = underline, 94 = blue or markups=[1, 4, 94]
    :param text: string/buffer to be marked up
    :param markups: a value or list of values representing ansi codes.
    :param resetvalue: string used to reset the terminal, default: "\33[0m"
    :param force: boolean, if set will add escape sequences regardless of tty. Defaults to the
                  class attr '_EUTESTER_FORCE_ANSI_ESCAPE' or the env variable:
                  'EUTESTER_FORCE_ANSI_ESCAPE' if it is set.
    :param allow_nonstandard: boolean, if True all markup values will be used. If false
                              the method will attempt to remap the markup value to a
                              standard ansi value to support tools such as Jenkins, etc.
                              Defaults to the class attr '._EUTESTER_NON_STANDARD_ANSI_SUPPORT'
                              or the environment variable 'EUTESTER_NON_STANDARD_ANSI_SUPPORT'
                              if set.
    returns a string with the provided 'text' formatted within ansi escape sequences
    """
    text = str(text)
    if not markups:
        return text
    if not isinstance(markups, list):
        markups = [markups]
    if force is None:
        force = os.environ.get('EUTESTER_FORCE_ANSI_ESCAPE', _EUTESTER_FORCE_ANSI_ESCAPE)
        if str(force).upper() == 'TRUE':
            force = True
        else:
            force = False
    if allow_nonstandard is None:
        allow_nonstandard = os.environ.get('EUTESTER_NON_STANDARD_ANSI_SUPPORT',
                                           _EUTESTER_NON_STANDARD_ANSI_SUPPORT)
        if str(allow_nonstandard).upper() == 'TRUE':
            allow_nonstandard = True
        else:
            allow_nonstandard = False
    if not force:
        if not (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()):
            return text
    if not allow_nonstandard:
        newmarkups = []
        for markup in markups:
            if markup > 90:
                newmarkups.append(markup-60)
            else:
                newmarkups.append(markup)
        markups = newmarkups
    lines = []
    markupvalues=";".join(str(x) for x in markups)
    for line in text.splitlines():
        lines.append("\033[{0}m{1}\033[0m".format(markupvalues, line))
    buf = "\n".join(lines)
    if text.endswith('\n') and not buf.endswith('\n'):
        buf += '\n'
    return buf
