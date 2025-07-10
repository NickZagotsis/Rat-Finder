import platform
import threading
import tkinter as tk
from os import getcwd
from tkinter import ttk
from datetime import datetime
from zoneinfo import available_timezones, ZoneInfo
from tkinter import messagebox, filedialog
from ttkwidgets.autocomplete import AutocompleteCombobox
from RatFinder.classes.rats.teamviewer import Teamviewer
from RatFinder.classes.utils.Tools.Directory_Listing import DirectoryListing
from RatFinder.classes.rats.anydesk import Anydesk
from os.path import join as pjoin

class Controller:
    """
    Controller class to handle the GUI logic and interactions.
    """
    def __init__(self, gui, shared_):
        """
        Initialize the Controller with the GUI instance and shared data.
        Parameters
        ----------
        gui: GUI
            GUI instance to interact with.
        shared_: Shared
            Shared data instance to store user selections.
        """
        self.gui = gui
        self.shared = shared_

    def parse(self, logger):
        """
        Parse the RATs and generate logs.
        Args:
            shared (Shared): Shared instance containing configuration and state.
            logger (Logger): Logger instance for logging.
        """
        try:
            if not self.shared.no_logging:
                self.shared.logger_instance.generate_general_logger()
                self.shared.logger.bind(category="general").info("Log initiated. General log created")

            self.shared.output = pjoin(self.shared.output, "RatFinder_Results", platform.uname()[1],
                                  datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))

            if not self.shared.no_logging:
                self.shared.logger.bind(category="general").info('Producing directory listing...')
            DirectoryListing(self.shared).directory_list()

            self.gui.root.after(0, lambda: self.gui.update_progress(33))

            if 'AnyDesk' in self.shared.rats:
                if not self.shared.no_logging:
                    logger.generate_anydesk_logger()
                    self.shared.logger.bind(category="anydesk").info("Log initiated. Anydesk log created")
                anydesk = Anydesk(self.shared)
                anydesk.parse()
                del self.shared.trace_files
                del anydesk

            self.gui.root.after(0, lambda: self.gui.update_progress(66))

            if 'TeamViewer' in self.shared.rats:
                if not self.shared.no_logging:
                    logger.generate_teamviewer_logger()
                    self.shared.logger.bind(category="teamviewer").info("Log initiated. Teamviewer log created")
                teamviewer = Teamviewer(self.shared)
                teamviewer.parse()
                del teamviewer

            self.gui.root.after(0, lambda: self.gui.update_progress(99))

        except Exception as e:
            self.shared.logger.bind(category="general").error(f"Uncaught exception: {str(e)}")
            self.gui.root.after(0, lambda: self.gui.window_pop("Error",f"Uncaught exception: {str(e)}"))
        else:
            self.shared.logger.bind(category="general").success(f"Program finished with no errors.")
            self.gui.root.after(0, lambda: self.gui.window_pop("Success",f"Program finished with no errors."))
        finally:
            self.gui.root.after(0, lambda: self.gui.update_progress(100))
            self.gui.root.after(0, lambda: self.parsing_buttons_toggle("!disabled"))

    def toggle_input_field(self):
        """
        Enable or disable the input button based on the selected directory listing option.
        Returns
        -------

        """
        if self.gui.dirlisting_var.get() == "Full":
            self.gui.input_button.state(["!disabled"])
        else:
            self.gui.input_button.state(["disabled"])

    def parsing_buttons_toggle(self, toggle):
        """
        This function is called when the start button is pressed and disables all buttons until the program is finished.
        Args:
            toggle: str
                Can only be !disabled or disabled
        """
        self.gui.timezone_combobox.state([toggle])
        self.gui.output_button.state([toggle])
        self.gui.input_button.state([toggle])
        self.gui.start_button.state([toggle])

    def start(self):
        """
        Start the RAT Finder process by gathering user inputs and closing the GUI.
        Returns
        -------

        """
        if not self.gui.get_rats():
            self.gui.messagebox.showerror("Error", "Please select at least one RAT.")
            return
        # if not self.gui.get_modules():
        #     self.gui.messagebox.showerror("Error", "Please select at least one module.")
        #     return
        if not self.gui.get_reports():
            self.gui.messagebox.showerror("Error", "Please select at least one report.")
            return

        dirlist_opt = self.gui.get_directory_listing()

        if dirlist_opt == "Only known locations":
            self.shared.full = False

        self.shared.output = self.gui.output_dir
        self.shared.input = self.gui.input_dir.replace('/', '\\')
        self.shared.no_logging = self.gui.nolog
        self.shared.rats = self.gui.get_rats()
        self.shared.modules = self.gui.modules
        self.shared.reports = self.gui.get_reports()
        self.shared.timezone = self.gui.get_timezone()

        if 'All' in self.shared.rats:
            self.shared.rats = self.gui.rats[1:] # Remove "All" from the list
        if 'All' in self.shared.modules:
            self.shared.modules = self.gui.modules[1:] # Remove "All" from the list
        if 'All' in self.shared.reports:
            self.shared.reports = self.gui.reports[1:] # Remove "All" from the list

        self.parsing_buttons_toggle("disabled")
        t = threading.Thread(target=self.parse, args=(self.shared.logger_instance,))
        t.start()
        #t.join() Do not use unless you want blocking



class GUI:
    """
    GUI class to create and manage the graphical user interface for the RAT Finder application.
    """

    def update_progress(self, percent):
        self.progress['value'] = percent
        self.progress_label.config(text=f"Progress: {percent:.0f}%")

    def window_pop(self, type_ ,message):
        if type_ == "Error":
            self.messagebox.showerror("Error", message)
        elif type_ == "Success":
            self.messagebox.showinfo("Success", message)

    def __init__(self, shared = None):
        self.rats = ["All","AnyDesk","TeamViewer"]
        self.reports = ['All', 'HTML', 'EXCEL', 'CSV']
        self.dirlisting_type = ["Only known locations","Full"]
        self.modules = ["All","Known Logs", "Registry"]
        self.nolog = False
        # Create main window
        self.root = tk.Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.title("RatFinder")
        self.center(500, 650)
        self.root.resizable(False, False)  # Prevent resizing

        self.menu = tk.Menu(self.root)
        self.settings = tk.Menu(self.menu, tearoff=False)
        self.settings.add_command(label="Toggle logging", command=self.no_log)

        self.menu.add_cascade(label="Settings", menu=self.settings)
        self.root.config(menu=self.menu)

        style = ttk.Style()
        style.configure("TProgressbar", thickness=20)  # Adjust thickness
        style.configure("TProgressbar", troughcolor='white', background='#4CAF50')

        # Main frame for padding
        main_frame = ttk.Frame(self.root, padding="10 10 10 10")
        main_frame.pack(fill="both", expand=True)

        # Timezone Selection
        timezone_frame = ttk.LabelFrame(main_frame, text="Select Timezone", padding="10 10 10 10")
        timezone_frame.pack(fill="x", pady=5)

        self.timezones = sorted(available_timezones())
        self.selected_timezone = tk.StringVar(value="Europe/Athens")

        self.timezone_combobox = AutocompleteCombobox(timezone_frame, textvariable=self.selected_timezone,
                                                      completevalues=self.timezones)
        self.timezone_combobox.pack(fill="x")



        # Input Directory Selection
        self.input_dir = getcwd()
        self.input_label = ttk.Label(main_frame, text=f"Input Directory: {self.input_dir}", anchor="w")
        self.input_label.pack(fill="x", pady=2)
        self.input_button = ttk.Button(main_frame, text="Select Input Directory", command=self.select_input_dir)
        self.input_button.state(["disabled"])
        self.input_button.pack(pady=5)

        # Output Directory Selection
        self.output_dir = getcwd()
        self.output_label = ttk.Label(main_frame, text=f"Output Directory: {self.output_dir}", anchor="w")
        self.output_label.pack(fill="x", pady=2)
        self.output_button = ttk.Button(main_frame, text="Select Output Directory", command=self.select_output_dir)
        self.output_button.pack(pady=5)

        # Rats Selection
        self.rat_checkboxes = self.create_frames(main_frame, "Select RATs",self.rats)

        # Modules Selection
        #self.modules_checkboxes = self.create_frames(main_frame, "Select Modules", self.modules)

        #Reports checkboxes
        self.reports_checkboxes = self.create_frames(main_frame, "Select Reports", self.reports)
        self.controller = Controller(self, shared)


        self.dirlisting_var = tk.StringVar(value="Only known locations")

        dirlisting_frame = ttk.LabelFrame(main_frame, text="Directory Listing", padding="10 10 10 10")
        dirlisting_frame.pack(fill="x", pady=5)

        for option in self.dirlisting_type:
            rb = ttk.Radiobutton(
                dirlisting_frame, text=option, value=option,
                variable=self.dirlisting_var, command=self.controller.toggle_input_field
            )
            rb.pack(anchor="w")

        self.directory_listing = [(opt, tk.IntVar(value=1 if opt == "Only known locations" else 0)) for opt in self.dirlisting_type]

        progress_frame = ttk.Frame(main_frame, padding="10 0 10 0")
        progress_frame.pack(fill="x", pady=5)

        self.progress_label = ttk.Label(progress_frame, text="Progress: 0%", font=("Arial", 10))
        self.progress_label.pack()

        self.progress = ttk.Progressbar(progress_frame, mode='determinate', maximum=100)
        self.progress.pack(fill="x", pady=10)


        self.messagebox = messagebox
        self.start_button = ttk.Button(main_frame, text="Start", command=self.controller.start)
        self.start_button.pack(pady=5)

        # Run the application
        self.root.mainloop()

    def get_timezone(self):
        return ZoneInfo(self.selected_timezone.get())

    def center(self, width, height):
        """
        Center the window on the screen with the given width and height.
        Parameters
        ----------
        width: int
        height: int

        Returns
        -------

        """
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = int((screen_width - width) / 2)
        y = int((screen_height - height) / 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    @staticmethod
    def create_frames(main_frame, text, given_list):
        """
        Create a frame with checkboxes for the given list of options.
        Parameters
        ----------
        main_frame: ttk.Frame
            The main frame to pack the checkboxes into.
        text: str
            The label for the frame.
        given_list: list[str]
            List of options to create checkboxes for.

        Returns
        -------

        """
        frame = ttk.LabelFrame(main_frame, text=text, padding="10 10 10 10")
        frame.pack(fill="x", pady=5)
        return GUI.create_checkboxes(frame, given_list)

    def on_closing(self):
        """
        Handle the window close event.
        Returns
        -------

        """
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.root.destroy()
            exit(0)

    def no_log(self):
        """
        Toggle the logging option.
        Returns
        -------

        """
        self.nolog = not self.nolog
        messagebox.showinfo("No logging", f"Logging has been {'disabled' if self.nolog else 'enabled'}")

    @staticmethod
    def create_checkboxes(parent, options):
        """
        Create checkboxes for the given options and pack them into the parent frame.
        Parameters
        ----------
        parent: ttk.Frame
        options: list[str]

        Returns
        -------

        """
        checkboxes = []
        for option in options:
            var = tk.IntVar()
            if option == "All" or option == "Only known locations":
                var.set(1)

            cb = ttk.Checkbutton(parent, text=option, variable=var)
            cb.pack(anchor="w")
            checkboxes.append((option, var))
        return checkboxes

    def get_rats(self):
        """
        Get the selected RATs from the checkboxes.
        Returns
        -------

        """
        selected = [rat for rat, var in self.rat_checkboxes if var.get()]
        return selected
        #messagebox.showinfo("Selected RATs", ", ".join(selected) if selected else "No RATs selected")

    def get_reports(self):
        """
        Get the selected report options from the checkboxes.
        Returns
        -------

        """
        selected = [report for report, var in self.reports_checkboxes if var.get()]
        return selected

    # def get_modules(self):
    #     selected = [module for module, var in self.modules_checkboxes if var.get()]
    #     return selected
        #messagebox.showinfo("Selected Modules", ", ".join(selected) if selected else "No modules selected")

    def get_directory_listing(self):
        """
        Get the selected directory listing option.
        Returns
        -------
            str:
                Dirlisting option
        """
        return self.dirlisting_var.get()

    def select_output_dir(self):
        """
        Open a file dialog to select the output directory.
        Returns
        -------

        """
        self.output_dir = filedialog.askdirectory().replace("/", "\\")
        if self.output_dir:
            self.output_label.config(text=f"Output Directory: {self.output_dir}")

    def select_input_dir(self):
        """
        Open a file dialog to select the input directory.
        Returns
        -------

        """
        self.input_dir = filedialog.askdirectory().replace("/", "\\")
        if self.input_dir:
            self.input_label.config(text=f"Input Directory: {self.input_dir}")
