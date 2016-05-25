import re

f = open('convert.txt')
with f:
    text = f.readlines()
start = False
end = False
block = ""
args = []
kwargs = {}
if text:
    print "_DEFAULT_CLI_ARGS = copy.copy(CliTestRunner._DEFAULT_CLI_ARGS)"
for line in text:
    text = str(line.strip())
    text = text.replace('self.parser.add_argument(', '')
    if not text or re.match(r'^\s*$', line):
        continue
    block += text
    if re.search(r'\)\s*$', line):
        block = block.strip(')').strip()
        #print 'got end of block!: ' + str(line)
        block = re.sub(',\s*[D|d]efault\s*:\s*[\w"\']+', '', block)
        block = block.replace("''", "")
        block = block.replace('""', '')
        #print 'block:{0}'.format(block)
        args = []
        kwargs = {}
        name = None

        # end of block parse the line
        parts = block.split(",")
        for part in parts:
            #print 'GOT PART START:' + str(part)
            if re.search("'$", part):
                is_string = True
            else:
                is_string = False
            part = part.strip()

            if not part or re.match(r'^\s*$', line):
                continue
            #print 'GOT PART:' + str(part)
            match = re.search('(\w.*\w)\s*=\s*([\w\'"].*\w)', part)
            if match:
                if is_string:
                    value = "{0}".format(match.groups()[1].strip())
                    #print 'is string: ' + str(value)
                else:
                    value = match.groups()[1].strip()
                if re.search("^\s*['\"]", value) and not value.endswith(value[0]):
                    value += value[0]
                kwargs[match.groups()[0].strip()] = value
                #print 'ADDED TO KWARGS:' + str(part)
            else:
                value = part
                match = re.search("^[\s'\"]*(-+)", value)
                if not name:
                    name = part.replace("-", "")
                if match:
                    value = value.lstrip("-")
                    value = str(value).replace("_", "-")
                    #value = str(match.groups()[0]) + value
                args.append(value)
                #print 'ADDED TO ARGS:' + str(part)
        #print "name:{0}\nargs:{1}\nkwargs{2}\n".format(name, args, kwargs)
        kwarg_str = ",\n                ".join("'{0}': {1}".format(key, kwargs[key]) for key in kwargs.keys())
        #print kwarg_str
        print "_DEFAULT_CLI_ARGS[{0}] = ".format(name) + "{"
        print "    'args': [{0}],".format(", ".join("{0}".format(x) for x in args))
        print "    'kwargs': { " + kwarg_str + " }}\n"
        block = ""
        #print "\n"
