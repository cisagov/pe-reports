"""Class methods for report charts."""

# Standard Python Libraries
import os

# Third-Party Libraries
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

# Factor to convert cm to inches
CM_CONVERSION_FACTOR = 2.54

# Get base directory to save images
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Charts:
    """Build charts."""

    def __init__(self, df, width, height, name, title, x_label, y_label):
        """Initialize chart class."""
        self.df = df
        self.title = title
        self.x_label = x_label
        self.y_label = y_label
        self.width = width
        self.height = height
        self.name = name

    def pie(self):
        """Build pie chart."""
        df = self.df
        width = self.width
        height = self.height
        name = self.name
        plt.rcParams.update({"figure.max_open_warning": 0})
        category_name = df.columns[0]
        value_name = df.columns[1]
        df = df.sort_values(by=value_name, ascending=False)
        category_column = df[category_name]
        value_column = df[df.columns[1]]
        labels = category_column
        plt.gca().axis("equal")

        def autopct(pct):
            """Get percentages for the pie chart slices > 10%."""
            return ("%1.0f%%" % pct) if pct > 1 else ""

        pie = plt.pie(
            value_column,
            startangle=0,
            radius=1,
            autopct=autopct,
            textprops={"color": "w", "fontsize": 7},
        )
        plt.legend(
            pie[0],
            labels,
            bbox_to_anchor=(1, 0.5),
            loc="center right",
            fontsize=7,
            bbox_transform=plt.gcf().transFigure,
            frameon=False,
        )
        plt.subplots_adjust(left=0.2, wspace=0.2)
        plt.gcf().set_size_inches(
            width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
        )
        plt.savefig(
            BASE_DIR + "/assets/" + name, transparent=True, dpi=500, bbox_inches="tight"
        )
        plt.clf()

    def stacked_bar(self):
        """Build stacked bar chart."""
        df = self.df
        title = self.title
        x_label = self.x_label
        y_label = self.y_label
        width = self.width
        height = self.height
        name = self.name
        color = ["#1357BE", "#D0342C"]
        df.plot(kind="bar", stacked=True, zorder=3, color=color)
        # Add title to chart
        plt.title(title, pad=15, fontsize=10)
        # Format chart's axis
        plt.xlabel(x_label, labelpad=10, fontdict={"size": 8})
        plt.ylabel(y_label, labelpad=10, fontdict={"size": 8})
        plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))
        plt.rc("axes", axisbelow=True)
        plt.grid(axis="y", zorder=0)
        plt.xticks(rotation=0)
        plt.ylim(ymin=0)
        # Set sizing for image
        plt.gcf().set_size_inches(
            width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
        )
        plt.tight_layout()
        # Save chart to assets directory
        plt.savefig(BASE_DIR + "/assets/" + name, transparent=True, dpi=500)
        plt.clf()

    def h_bar(self):
        """Build horizontal bar chart."""
        df = self.df
        x_label = self.x_label
        y_label = self.y_label
        width = self.width
        height = self.height
        name = self.name
        plt.rcParams.update({"figure.max_open_warning": 0})
        category_name = df.columns[0]
        value_name = df.columns[1]
        category_column = df[category_name].str.replace("Vulnerable Product - ", "")
        value_column = df[df.columns[1]]
        bar_width = 0.6
        fig, ax = plt.subplots()
        ax.spines.right.set_visible(False)
        ax.spines.top.set_visible(False)
        # Generate horizontal bar chart
        plt.barh(df.index, value_column, bar_width, align="center", color="#466fc6")
        # Specify axis atributes
        plt.xticks(fontsize=7)
        plt.yticks(fontsize=7)
        plt.xlim(xmin=0)
        plt.gca().xaxis.set_major_locator(MaxNLocator(integer=True))
        plt.gca().set_ylim(-1.0, len(category_column))
        plt.gca().set_yticks(df.index)
        plt.gca().set_yticklabels(category_column)
        plt.gca().set_xlabel(x_label, fontdict={"size": 8})
        plt.gca().set_ylabel(y_label)
        # Set sizing for image
        plt.gcf().set_size_inches(
            width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
        )
        plt.tight_layout()
        # Add data labels to each bar if greater than 0
        for i in range(len(df)):
            if df.loc[i, value_name] > 0:
                label = df.loc[i, value_name]
                plt.annotate(
                    label,  # this is the text
                    (df.loc[i, value_name], i),  # this is the point to label
                    textcoords="offset points",  # how to position the text
                    xytext=(7, -3),  # distance from text to points (x,y)
                    ha="center",  # horizontal alignment can be left, right or center
                    fontsize=8,
                )
        # Save chart to assets directory
        plt.savefig(
            BASE_DIR + "/assets/" + name, transparent=True, dpi=500, bbox_inches="tight"
        )
        plt.clf()

    def line_chart(self):
        """Build line chart."""
        df = self.df
        x_label = self.x_label
        y_label = self.y_label
        width = self.width
        height = self.height
        name = self.name
        color = ["#1357BE", "#D0342C"]
        fig, ax = plt.subplots()
        ax.spines["right"].set_visible(False)
        ax.spines["top"].set_visible(False)
        plt.set_loglevel("WARNING")
        # Generate lines for chart and add data labels
        for col in range(len(df.columns)):
            plt.plot(
                df.index, df[df.columns[col]], color=color[col], label=df.columns[col]
            )
            for i, j in df[df.columns[col]].items():
                if int(j):
                    plt.annotate(
                        str(int(j)),
                        xy=(i, j),
                        textcoords="offset points",  # how to position the text
                        xytext=(
                            0,
                            5,
                        ),  # distance from text to points (x,y)
                        ha="center",  # horizontal alignment can be left, right or center
                    )
        # Specify axis atributes
        plt.ylim(ymin=0, ymax=int(df[df.columns].max().max() * 1.15))
        plt.xticks(fontsize=7)
        plt.yticks(fontsize=7)
        plt.gca().set_ylabel(y_label, labelpad=10, fontdict={"size": 8})
        plt.xlabel(x_label, labelpad=10, fontdict={"size": 8})
        plt.xticks(rotation=0)
        plt.grid(axis="y")
        # Add legend
        plt.legend(loc="upper right")
        # Set sizing for image
        plt.gcf().set_size_inches(
            width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
        )
        plt.tight_layout()
        # Save chart to assets directory
        plt.savefig(
            BASE_DIR + "/assets/" + name, transparent=True, dpi=500, bbox_inches="tight"
        )
        plt.clf()
