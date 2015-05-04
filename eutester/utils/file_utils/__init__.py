

@staticmethod
def render_file_template(src, dest, **kwargs):
    import jinja2
    with open(src) as sfile:
        templ = jinja2.Template(sfile.read())
        with open(dest, 'w') as dfile:
            dfile.write(templ.render(kwargs))
