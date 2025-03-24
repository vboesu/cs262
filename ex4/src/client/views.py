import tkinter as tk


class PlaceholderEntry(tk.Entry):
    """
    A subclass of tk.Entry that includes placeholder text functionality.
    """

    def __init__(self, master=None, placeholder="PLACEHOLDER", color="grey", **kwargs):
        super().__init__(master, **kwargs)

        self.placeholder = placeholder
        self.placeholder_color = color
        self.default_fg_color = self["fg"]

        self.bind("<FocusIn>", self.foc_in)
        self.bind("<FocusOut>", self.foc_out)

        self.put_placeholder()

    def put_placeholder(self):
        """Insert placeholder text and set the color to placeholder color."""
        self.insert(0, self.placeholder)
        self["fg"] = self.placeholder_color

    def foc_in(self, *args):
        """Remove placeholder text when focus is gained."""
        if self["fg"] == self.placeholder_color:
            self.delete("0", "end")
            self["fg"] = self.default_fg_color

    def foc_out(self, *args):
        """Re-insert placeholder text if entry is empty when focus is lost."""
        if not self.get():
            self.put_placeholder()
