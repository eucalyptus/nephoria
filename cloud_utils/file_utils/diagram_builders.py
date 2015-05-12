
import blockdiag
import nwdiag
import seqdiag
import actdiag


def _BuildDiagram(diag_class, source_json, filename):
    parser = diag_class.parser
    builder = diag_class.builder
    drawer = diag_class.drawer
    tree = parser.parse_string(source_json)
    diagram = builder.ScreenNodeBuilder.build(tree)
    draw = drawer.DiagramDraw('PNG', diagram, filename=filename)
    draw.draw()
    draw.save()
    return draw


def BuildNetworkDiagram(source_json, filename):
    return _BuildDiagram(diag_class=nwdiag, source_json=source_json, filename=filename)


def BuildBlockDiagram(source_json, filename):
    return _BuildDiagram(diag_class=blockdiag, source_json=source_json, filename=filename)


def BuildSequenceDiagram(source_json, filename):
    return _BuildDiagram(diag_class=seqdiag, source_json=source_json, filename=filename)


def BuildActivityDiagram(source_json, filename):
    return _BuildDiagram(diag_class=actdiag, source_json=source_json, filename=filename)
