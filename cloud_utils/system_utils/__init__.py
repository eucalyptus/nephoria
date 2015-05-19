import subprocess


def local(cmd):
        """
        Run a command on the localhost
        :param cmd: str representing the command to be run
        :return: :raise: CalledProcessError on non-zero return code
        """
        args = cmd.split()
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   bufsize=4096)
        output, unused_err = process.communicate()
        retcode = process.poll()
        if retcode:
            error = subprocess.CalledProcessError(retcode, cmd)
            error.output = output
            raise error
        return output.split("\n")
