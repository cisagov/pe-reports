"""Models to manage grahical attributes of presentation layouts, paragraphs, and charts."""

# Third-Party Libraries
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_LEGEND_POSITION
from pptx.util import Pt


class Paragraph:
    """Simple class to call text frame atributes."""

    def shapes(self, slide):
        """Create a text frame."""
        for shape in slide.shapes:
            if not shape.has_text_frame:
                continue
        return shape

    def shapes_find(self, slide):
        """Find text frames."""
        for shape in slide.shapes:
            print(shape.name)
        return

    def text_frame(self, shape):
        """Clear the content of a text frame."""
        text_frame = shape.text_frame
        text_frame.clear()
        return text_frame

    def text_frame_ov_val(self, slide, shape, name):
        """Text style for overview page values."""
        for shape in slide.shapes:
            if shape.name == name:
                text_frame = shape.text_frame
                text_frame.clear()
        return text_frame

    def text_frame_key_metric(self, slide, shape, name):
        """Text style for metrics."""
        for shape in slide.shapes:
            if shape.name == name:
                text_frame = shape.text_frame
                text_frame.clear()
        return text_frame

    def text_style_title(self, font):
        """Text style for cover page title."""
        font.name = "Calibri"
        font.size = Pt(28)
        font.color.rgb = RGBColor(255, 255, 255)
        return font

    def text_style_key_metric(self, font):
        """Need to insert docstring here."""
        font.name = "Calibri"
        font.size = Pt(12)
        font.color.rgb = RGBColor(255, 255, 255)
        return font

    def text_style_ov_val(self, font):
        """Text style for overview page values."""
        font.name = "Calibri"
        font.size = Pt(28)
        font.color.rgb = RGBColor(3, 37, 126)
        return font


class Graph:
    """Simple class to call chart attributes."""

    def bar(self, slide, chart):
        """Medium bar chart."""
        chart.font.size = Pt(10)
        chart.font.rgb = (20, 200, 100)
        chart.has_legend = True
        chart.legend.position = XL_LEGEND_POSITION.BOTTOM
        chart.legend.include_in_layout = False
        return

    def bar_sm(self, slide, chart):
        """Small bar chart."""
        chart.font.size = Pt(10)
        chart.font.rgb = (20, 200, 100)
        return

    def bar_med_100(self, slide, chart):
        """Medium bar chart with percentages."""
        chart.font.size = Pt(10)
        chart.font.rgb = (20, 200, 100)
        return

    def line_med(self, slide, chart):
        """Medium line chart."""
        chart.font.size = Pt(10)
        chart.font.rgb = (20, 200, 100)
        chart.has_legend = True
        chart.legend.position = XL_LEGEND_POSITION.BOTTOM
        chart.legend.include_in_layout = False
        return
