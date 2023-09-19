"""Class methods for report charts."""

# Standard Python Libraries
import os

# Third-Party Libraries
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

matplotlib.use("Agg")


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
        color = ["#7aa5c1", "#e08493"]
        fig, ax = plt.subplots()
        ax.spines["right"].set_visible(False)
        ax.spines["top"].set_visible(False)
        plt.set_loglevel("WARNING")
        # Plot first line on chart
        plt.plot(
            df.index,
            df[df.columns[0]],
            color=color[0],
            label=df.columns[0],
            linewidth=3,
            marker=".",
            markersize=10,
        )
        # If there is another column chart the second line
        if len(df.columns) == 2:
            plt.plot(
                df.index,
                df[df.columns[1]],
                color=color[1],
                label=df.columns[1],
                linewidth=3,
                linestyle="dashed",
                marker=".",
                markersize=10,
            )
        # Set the y-max to 110% of the max y value
        y_max = int(df[df.columns].max().max() * 1.1)
        plt.ylim(ymin=0, ymax=y_max * 1.10)
        # Place the legend in the upper right corner
        plt.legend(loc="upper right")
        # Set size of the chart
        plt.gcf().set_size_inches(
            width / CM_CONVERSION_FACTOR, height / CM_CONVERSION_FACTOR
        )
        # Format tick marks and grid layout
        plt.xticks(fontsize=7)
        plt.yticks(fontsize=7)
        plt.gca().set_ylabel(y_label, labelpad=10, fontdict={"size": 8})
        plt.xlabel(x_label, labelpad=10, fontdict={"size": 8})
        plt.xticks(rotation=0)
        plt.grid(axis="y")
        plt.tight_layout()

        # Add data labels
        # Loop through the dataframe
        for row in df.itertuples():
            # Check if there is only one row of values
            if len(row) == 2:
                plt.annotate(
                    str(int(row[1])),
                    xy=(row[0], row[1]),
                    textcoords="offset points",  # Set the manner to position the text
                    xytext=(
                        0,
                        8,
                    ),  # Distance from text to points (x,y)
                    ha="center",  # Set horizontal alignment to center
                    color="#003e67",
                )
                # Check if there are two rows of data
            elif len(row) == 3:
                # Check if the two values are within 1/10th of the max y value
                value_diff = abs(row[1] - row[2])
                if value_diff < y_max / 10:
                    # If the values are on the bottom quarter of the graph don't label below values
                    if min(row[1], row[2]) < y_max / 4:
                        y1 = y2 = max(row[1], row[2])
                        if row[1] > row[2]:
                            y1_offset = 18
                            y2_offset = 8
                        else:
                            y1_offset = 8
                            y2_offset = 18
                    # If the values are not in the bottom quarter place the lower value below the point
                    else:
                        y1 = row[1]
                        y2 = row[2]
                        if row[1] > row[2]:
                            y1_offset = 8
                            y2_offset = -17
                        else:
                            y1_offset = -17
                            y2_offset = 8
                # If values are not close to each other put the labels directly above the value
                else:
                    y1 = row[1]
                    y2 = row[2]
                    y1_offset = 8
                    y2_offset = 8

                # Annotate the data points
                plt.annotate(
                    str(int(row[1])),
                    xy=(row[0], y1),
                    textcoords="offset points",  # Set how to position the text
                    xytext=(
                        0,
                        y1_offset,
                    ),  # Distance from text to points (x,y)
                    ha="center",  # Horizontal alignment can be left, right or center
                    color="#005288",
                )
                plt.annotate(
                    str(int(row[2])),
                    xy=(row[0], y2),
                    textcoords="offset points",  # Set how to position the text
                    xytext=(
                        0,
                        y2_offset,
                    ),  # Distance from text to points (x,y)
                    ha="center",  # Set horizontal alignment to center
                    # fontsize=2,
                    color="#c41230",
                )
        # Save chart to assets directory
        plt.savefig(
            BASE_DIR + "/assets/" + name, transparent=True, dpi=500, bbox_inches="tight"
        )
        plt.clf()
