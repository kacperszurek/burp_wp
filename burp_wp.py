#  ____  _   _ ____  ____   __        ______
# | __ )| | | |  _ \|  _ \  \ \      / /  _ \ 
# |  _ \| | | | |_) | |_) |  \ \ /\ / /| |_) |
# | |_) | |_| |  _ <|  __/    \ V  V / |  __/ 
# |____/ \___/|_| \_\_|        \_/\_/  |_|    
#
# MIT License
#
# Copyright (c) 2018 Kacper Szurek
import collections
import hashlib
import json
import os
import re
import shutil
import threading
import time
import traceback
import urllib2
import urlparse
from array import array
from base64 import b64encode, b64decode
from collections import defaultdict
from distutils.version import LooseVersion
from itertools import chain
from threading import Lock

from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IHttpListener
from burp import IIntruderPayloadGenerator
from burp import IIntruderPayloadGeneratorFactory
from burp import IMessageEditorController
from burp import IParameter
from burp import IScanIssue
from burp import ITab
from burp import IScannerCheck

from java.awt import Component
from java.awt import Cursor
from java.awt import Desktop
from java.awt import Dimension
from java.awt.event import ActionListener
from java.awt.event import ItemEvent
from java.awt.event import ItemListener
from java.awt.event import MouseAdapter
from java.net import URL, URI
from java.security import KeyFactory
from java.security import Signature
from java.security.spec import X509EncodedKeySpec
from java.util import ArrayList
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JComboBox
from javax.swing import JEditorPane
from javax.swing import JFileChooser
from javax.swing import JLabel
from javax.swing import JMenuItem
from javax.swing import JOptionPane
from javax.swing import JPanel
from javax.swing import JProgressBar
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTabbedPane
from javax.swing import JTable
from javax.swing import JTextField
from javax.swing.event import DocumentListener
from javax.swing.table import AbstractTableModel
from org.python.core.util import StringUtil

BURP_WP_VERSION = '0.1.2'
INTERESTING_CODES = [200, 401, 403, 301]
DB_NAME = "burp_wp_database.db"


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory, IMessageEditorController, IScannerCheck):
    config = {}

    def print_debug(self, message):
        if self.config.get('debug', False):
            self.callbacks.printOutput(message)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks

        self.callbacks.printOutput("WordPress Scanner version {}".format(BURP_WP_VERSION))

        self.helpers = callbacks.getHelpers()

        self.initialize_config()

        self.callbacks.setExtensionName("WordPress Scanner")

        # createMenuItems
        self.callbacks.registerContextMenuFactory(self)

        # processHttpMessage
        self.callbacks.registerHttpListener(self)

        self.callbacks.registerIntruderPayloadGeneratorFactory(IntruderPluginsGenerator(self))
        self.callbacks.registerIntruderPayloadGeneratorFactory(IntruderThemesGenerator(self))
        self.callbacks.registerIntruderPayloadGeneratorFactory(IntruderPluginsThemesGenerator(self))

        # doPassiveScan
        self.callbacks.registerScannerCheck(self)

        self.initialize_variables()
        self.initialize_gui()

        # getTabCaption, getUiComponent
        # This must be AFTER panel_main initialization
        self.callbacks.addSuiteTab(self)

        self.initialize_database()

    def initialize_config(self):
        temp_config = self.callbacks.loadExtensionSetting("config")
        if temp_config and len(temp_config) > 10:
            try:
                self.config = json.loads(b64decode(temp_config))
                self.print_debug("[+] initialize_config configuration: {}".format(self.config))
            except:
                self.print_debug("[-] initialize_config cannot load configuration: {}".format(traceback.format_exc()))
        else:
            self.print_debug("[+] initialize_config new configuration")
            self.config = {'active_scan': True, 'database_path': os.path.join(os.getcwd(), DB_NAME),
                           'wp_content': 'wp-content', 'full_body': False, 'all_vulns': False, 'scan_type': 1,
                           'debug': False, 'auto_update': True, 'last_update': 0, 'sha_plugins': '', 'sha_themes': '',
                           'print_info': False}

    def initialize_variables(self):
        self.is_burp_pro = True if "Professional" in self.callbacks.getBurpVersion()[0] else False
        self.regexp_version_number = re.compile("ver=([0-9.]+)", re.IGNORECASE)
        self.regexp_stable_tag = re.compile(r"(?:stable tag|version):\s*(?!trunk)([0-9a-z.-]+)", re.IGNORECASE)
        self.regexp_version_from_changelog = re.compile(
            r"[=]+\s+(?:v(?:ersion)?\s*)?([0-9.-]+)[ \ta-z0-9().\-,]*[=]+",
            re.IGNORECASE)

        self.list_issues = ArrayList()
        self.lock_issues = Lock()
        self.lock_update_database = Lock()

        self.database = {'plugins': collections.OrderedDict(), 'themes': collections.OrderedDict()}
        self.list_plugins_on_website = defaultdict(list)

    def initialize_gui(self):
        class CheckboxListener(ItemListener):
            def __init__(self, extender, name):
                self.extender = extender
                self.name = name

            def itemStateChanged(self, e):
                if e.getStateChange() == ItemEvent.SELECTED:
                    self.extender.update_config(self.name, True)
                else:
                    self.extender.update_config(self.name, False)

        class ComboboxListener(ActionListener):
            def __init__(self, extender, name):
                self.extender = extender
                self.name = name

            def actionPerformed(self, action_event):
                selected = self.extender.combobox_scan_type.getSelectedItem().get_key()
                self.extender.update_config(self.name, selected)

        class TextfieldListener(DocumentListener):
            def __init__(self, extender):
                self.extender = extender

            def changedUpdate(self, document):
                self._do(document)

            def removeUpdate(self, document):
                self._do(document)

            def insertUpdate(self, document):
                self._do(document)

            def _do(self, document):
                wp_content = self.extender.textfield_wp_content.getText().replace("/", "")
                self.extender.update_config('wp_content', wp_content)

        class CopyrightMouseAdapter(MouseAdapter):
            def __init__(self, url):
                self.url = URI.create(url)

            def mouseClicked(self, event):
                if Desktop.isDesktopSupported() and Desktop.getDesktop().isSupported(Desktop.Action.BROWSE):
                    try:
                        Desktop.getDesktop().browse(self.url)
                    except:
                        self._print_debug("[-] CopyrightMouseAdapter: {}".format(traceback.format_exc()))

        class ComboboxItem:
            def __init__(self, key, val):
                self._key = key
                self._val = val

            def get_key(self):
                return self._key

            # Set label inside ComboBox
            def __repr__(self):
                return self._val

        panel_upper = JPanel()
        panel_upper.setLayout(BoxLayout(panel_upper, BoxLayout.Y_AXIS))

        panel_update = JPanel()
        panel_update.setLayout(BoxLayout(panel_update, BoxLayout.X_AXIS))
        panel_update.setAlignmentX(Component.LEFT_ALIGNMENT)

        self.button_update = JButton("Update", actionPerformed=self.button_update_on_click)
        self.button_update.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_update.add(self.button_update)

        self.progressbar_update = JProgressBar()
        self.progressbar_update.setMaximumSize(self.progressbar_update.getPreferredSize())
        self.progressbar_update.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_update.add(self.progressbar_update)

        self.label_update = JLabel()
        self.label_update.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_update.add(self.label_update)

        panel_upper.add(panel_update)

        checkbox_active_scan = JCheckBox("Use readme.txt for detecting plugins version. This option sends additional request to website",
                                         self.config.get('active_scan', False))
        checkbox_active_scan.addItemListener(CheckboxListener(self, "active_scan"))
        panel_upper.add(checkbox_active_scan)

        checkbox_full_body = JCheckBox("Scan full response body (normally we check only URL)",
                                       self.config.get('full_body', False))
        checkbox_full_body.addItemListener(CheckboxListener(self, "full_body"))
        panel_upper.add(checkbox_full_body)

        checkbox_all_vulns = JCheckBox("Print all plugin vulnerabilities regarding detected version",
                                       self.config.get('all_vulns', False))
        checkbox_all_vulns.addItemListener(CheckboxListener(self, "all_vulns"))
        panel_upper.add(checkbox_all_vulns)

        checkbox_print_info = JCheckBox(
            "Print info about discovered plugins even if they don't have known vulnerabilities",
            self.config.get('print_info', False))
        checkbox_print_info.addItemListener(CheckboxListener(self, "print_info"))
        panel_upper.add(checkbox_print_info)

        checkbox_auto_update = JCheckBox("Enable auto update", self.config.get('auto_update', True))
        checkbox_auto_update.addItemListener(CheckboxListener(self, "auto_update"))
        panel_upper.add(checkbox_auto_update)

        checkbox_debug = JCheckBox("Enable debug mode", self.config.get('debug', False))
        checkbox_debug.addItemListener(CheckboxListener(self, "debug"))
        panel_upper.add(checkbox_debug)

        panel_what_detect = JPanel()
        panel_what_detect.setLayout(BoxLayout(panel_what_detect, BoxLayout.X_AXIS))
        panel_what_detect.setAlignmentX(Component.LEFT_ALIGNMENT)

        label_what_detect = JLabel("What detect: ")
        label_what_detect.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_what_detect.add(label_what_detect)

        self.combobox_scan_type = JComboBox()
        self.combobox_scan_type.addItem(ComboboxItem(1, "Plugins and Themes"))
        self.combobox_scan_type.addItem(ComboboxItem(2, "Only plugins"))
        self.combobox_scan_type.addItem(ComboboxItem(3, "Only themes"))
        self.combobox_scan_type.addActionListener(ComboboxListener(self, "scan_type"))
        self.combobox_scan_type.setMaximumSize(Dimension(200, 30))
        self.combobox_scan_type.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_what_detect.add(self.combobox_scan_type)

        label_wp_content = JLabel("Custom wp-content:")
        label_wp_content.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_what_detect.add(label_wp_content)

        self.textfield_wp_content = JTextField(self.config.get('wp_content', 'wp-content'))
        self.textfield_wp_content.getDocument().addDocumentListener(TextfieldListener(self))
        self.textfield_wp_content.setMaximumSize(Dimension(250, 30))
        self.textfield_wp_content.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_what_detect.add(self.textfield_wp_content)

        panel_upper.add(panel_what_detect)

        panel_choose_file = JPanel()
        panel_choose_file.setLayout(BoxLayout(panel_choose_file, BoxLayout.X_AXIS))
        panel_choose_file.setAlignmentX(Component.LEFT_ALIGNMENT)

        label_database_path = JLabel("Database path: ")
        label_database_path.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_choose_file.add(label_database_path)

        button_choose_file = JButton("Choose file", actionPerformed=self.button_choose_file_on_click)
        button_choose_file.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_choose_file.add(button_choose_file)

        self.textfield_database_path = JTextField(self.config.get('database_path', DB_NAME))
        self.textfield_database_path.setEditable(False)
        self.textfield_database_path.setMaximumSize(Dimension(250, 30))
        self.textfield_database_path.setAlignmentX(Component.LEFT_ALIGNMENT)
        panel_choose_file.add(self.textfield_database_path)

        panel_upper.add(panel_choose_file)

        panel_buttons = JPanel()
        panel_buttons.setLayout(BoxLayout(panel_buttons, BoxLayout.X_AXIS))
        panel_buttons.setAlignmentX(Component.LEFT_ALIGNMENT)

        button_clear_issues = JButton("Clear issues list", actionPerformed=self.button_clear_issues_on_click)
        panel_buttons.add(button_clear_issues)

        button_force_update = JButton("Force update", actionPerformed=self.button_force_update_on_click)
        panel_buttons.add(button_force_update)

        button_reset_to_default = JButton("Reset settings to default",
                                          actionPerformed=self.button_reset_to_default_on_click)
        panel_buttons.add(button_reset_to_default)

        panel_upper.add(panel_buttons)

        panel_copyright = JPanel()
        panel_copyright.setLayout(BoxLayout(panel_copyright, BoxLayout.X_AXIS))
        panel_copyright.setAlignmentX(Component.LEFT_ALIGNMENT)

        label_copyright1 = JLabel("<html><a href='#/'>WordPress Scanner {}</a></html>".format(BURP_WP_VERSION))
        label_copyright1.setAlignmentX(Component.LEFT_ALIGNMENT)
        label_copyright1.setCursor(Cursor(Cursor.HAND_CURSOR))
        label_copyright1.addMouseListener(CopyrightMouseAdapter("https://github.com/kacperszurek/burp_wp"))
        label_copyright1.setMaximumSize(label_copyright1.getPreferredSize())
        panel_copyright.add(label_copyright1)

        label_copyright2 = JLabel("<html>&nbsp;by <a href='#'>Kacper Szurek</a>.</html>")
        label_copyright2.setAlignmentX(Component.LEFT_ALIGNMENT)
        label_copyright2.setCursor(Cursor(Cursor.HAND_CURSOR))
        label_copyright2.addMouseListener(CopyrightMouseAdapter("https://security.szurek.pl/"))
        label_copyright2.setMaximumSize(label_copyright2.getPreferredSize())
        panel_copyright.add(label_copyright2)

        label_copyright3 = JLabel(
            "<html>&nbsp;Vulnerabilities database by <a href='#/'>WPScan</a></html>")
        label_copyright3.setAlignmentX(Component.LEFT_ALIGNMENT)
        label_copyright3.setCursor(Cursor(Cursor.HAND_CURSOR))
        label_copyright3.addMouseListener(CopyrightMouseAdapter("https://wpscan.org/"))
        panel_copyright.add(label_copyright3)

        panel_upper.add(panel_copyright)

        self.table_issues = IssuesTableModel(self)

        table_issues_details = IssuesDetailsTable(self, self.table_issues)
        table_issues_details.setAutoCreateRowSorter(True)
        panel_center = JScrollPane(table_issues_details)

        self.panel_bottom = JTabbedPane()
        self.panel_bottom_request1 = self.callbacks.createMessageEditor(self, True)
        self.panel_bottom_response1 = self.callbacks.createMessageEditor(self, True)
        self.panel_bottom_request2 = self.callbacks.createMessageEditor(self, True)
        self.panel_bottom_response2 = self.callbacks.createMessageEditor(self, True)

        self.panel_bottom_advisory = JEditorPane()
        self.panel_bottom_advisory.setEditable(False)
        self.panel_bottom_advisory.setEnabled(True)
        self.panel_bottom_advisory.setContentType("text/html")

        self.panel_bottom.addTab("Advisory", JScrollPane(self.panel_bottom_advisory))
        self.panel_bottom.addTab("Request 1", JScrollPane(self.panel_bottom_request1.getComponent()))
        self.panel_bottom.addTab("Response 1", JScrollPane(self.panel_bottom_response1.getComponent()))
        self.panel_bottom.addTab("Request 2", JScrollPane(self.panel_bottom_request2.getComponent()))
        self.panel_bottom.addTab("Response 2", JScrollPane(self.panel_bottom_response2.getComponent()))

        split_panel_upper = JSplitPane(JSplitPane.VERTICAL_SPLIT, panel_upper, panel_center)
        self.panel_main = JSplitPane(JSplitPane.VERTICAL_SPLIT, split_panel_upper, self.panel_bottom)

    def initialize_database(self):
        last_update = time.strftime("%d-%m-%Y %H:%M", time.localtime(self.config.get('last_update', 0)))
        update_started = False

        if self.config.get('auto_update', True):
            if (self.config.get('last_update', 0) + (60 * 60 * 24)) < int(time.time()):
                self.print_debug("[*] initialize_database Last check > 24h")
                self.button_update_on_click(None)
                update_started = True
            else:
                self.print_debug("[*] initialize_database last update: {}".format(last_update))

        database_path = self.config.get('database_path', DB_NAME)
        self.print_debug("[*] initialize_database database path: {}".format(database_path))
        if os.path.exists(database_path):
            try:
                with open(database_path, "rb") as fp:
                    self.database = json.load(fp)
                themes_length = len(self.database['themes'])
                plugins_length = len(self.database['plugins'])
                update_text = "Themes: {}, Plugins: {}, Last update: {}".format(themes_length, plugins_length,
                                                                                last_update)
                self.label_update.setText(update_text)
            except Exception as e:
                self.label_update.setText("Cannot load database: {}".format(e))
                self.print_debug("[-] initialize_database cannot load database: {}".format(traceback.format_exc()))
                if not update_started:
                    self.button_force_update_on_click(None)
        else:
            self.print_debug("[-] initialize_database database does not exist")
            if not update_started:
                self.button_force_update_on_click(None)

    def button_force_update_on_click(self, msg):
        self.print_debug("[+] button_force_update_on_click")

        self.update_config('sha_plugins', '')
        self.update_config('sha_themes', '')
        
        self.button_update_on_click(None)

    def button_reset_to_default_on_click(self, msg):
        self.print_debug("[+] button_reset_to_default_on_click")
        self.callbacks.saveExtensionSetting("config", "")
        JOptionPane.showMessageDialog(self.panel_main, "Please reload extension")
        self.callbacks.unloadExtension()

    def button_clear_issues_on_click(self, msg):
        self.print_debug("[+] button_clear_issues_on_click")
        self.lock_issues.acquire()
        row = self.list_issues.size()
        self.list_issues.clear()
        self.table_issues.fireTableRowsDeleted(0, row)
        self.panel_bottom_advisory.setText("")
        self.panel_bottom_request1.setMessage("", True)
        self.panel_bottom_response1.setMessage("", False)
        self.panel_bottom_request2.setMessage("", True)
        self.panel_bottom_response2.setMessage("", False)
        self.lock_issues.release()
        self.list_plugins_on_website = defaultdict(list)

    def button_update_on_click(self, msg):
        threading.Thread(target=self.update_database_wrapper).start()

    def button_choose_file_on_click(self, msg):
        file_chooser = JFileChooser()
        return_value = file_chooser.showSaveDialog(self.panel_main)
        if return_value == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            old_file_path = self.config.get('database_path', DB_NAME)
            file_path = selected_file.getPath()
            if file_path == old_file_path:
                self.print_debug("[+] button_choose_file_on_click the same database file")
                return

            if selected_file.exists():
                try:
                    with open(file_path, "rb") as fp:
                        temp_load = json.load(fp)
                    if "themes" in temp_load and "plugins" in temp_load:
                        self.database = temp_load
                        self.textfield_database_path.setText(file_path)
                        self.update_config('database_path', file_path)
                        self.update_config('last_update', int(time.time()))
                        self.print_debug("[+] button_choose_file_on_click offline database installed")
                        return
                except:
                    self.print_debug("[+] button_choose_file_on_click cannot load offline database: {}".format(
                        traceback.format_exc()))

                result = JOptionPane.showConfirmDialog(self.panel_main, "The file exists, overwrite?", "Existing File",
                                                       JOptionPane.YES_NO_OPTION)
                if result != JOptionPane.YES_OPTION:
                    return

            self.textfield_database_path.setText(file_path)
            self.print_debug("[+] button_choose_file_on_click new database path, force update")
            self.update_config('database_path', file_path)
            self.button_force_update_on_click(None)

    def update_config(self, key, val):
        try:
            self.config[key] = val
            temp_config = b64encode(json.dumps(self.config, ensure_ascii=False))
            self.callbacks.saveExtensionSetting("config", temp_config)
            self.print_debug("[+] Config updated for key {}".format(key))
            if key == "last_update":
                last_update = time.strftime("%d-%m-%Y %H:%M", time.localtime(self.config.get('last_update', 0)))
                themes_length = len(self.database['themes'])
                plugins_length = len(self.database['plugins'])
                update_text = "Themes: {}, Plugins: {}, Last update: {}".format(themes_length, plugins_length,
                                                                                last_update)
                self.label_update.setText(update_text)
                self.print_debug("[*] {}".format(update_text))
        except:
            self.print_debug("[-] update_config: {}".format(traceback.format_exc()))

    def update_database_wrapper(self):
        if not self.lock_update_database.acquire(False):
            self.print_debug("[*] update_database update already running")
            return
        try:
            self.button_update.setEnabled(False)

            self.print_debug("[+] update_database update started")
            if self._update_database():
                try:
                    with open(self.config.get('database_path'), "wb") as fp:
                        json.dump(self.database, fp)
                    self.update_config('last_update', int(time.time()))
                except:
                    self.print_debug("[-] update_database cannot save database: {}".format(traceback.format_exc()))
                    return

                self.print_debug("[+] update_database update finish")
        except:
            self.print_debug("[+] update_database update error")
        finally:
            self.lock_update_database.release()
            self.progressbar_update.setValue(100)
            self.progressbar_update.setStringPainted(True)
            self.button_update.setEnabled(True)

    def _make_http_request_wrapper(self, original_url):
        try:
            java_url = URL(original_url)
            request = self.helpers.buildHttpRequest(java_url)
            response = self.callbacks.makeHttpRequest(java_url.getHost(), 443, True, request)           
            response_info = self.helpers.analyzeResponse(response)
            if response_info.getStatusCode() in INTERESTING_CODES:
                return self.helpers.bytesToString(response)[response_info.getBodyOffset():].encode("latin1")
            else:
                self.print_debug("[-] _make_http_request_wrapper request failed")
                return None
        except:
            self.print_debug("[-] _make_http_request_wrapper failed: {}".format(traceback.format_exc()))
            return None

    def _update_database(self):
        dict_files = {'plugins': 'https://data.wpscan.org/plugins.json',
                      'themes': 'https://data.wpscan.org/themes.json'}

        progress_divider = len(dict_files) * 2
        progress_adder = 0
        for _type, url in dict_files.iteritems():
            try:
                temp_database = collections.OrderedDict()

                sha_url = "{}.sha512".format(url)
                sha_original = self._make_http_request_wrapper(sha_url)
                if not sha_original:
                    return False

                if self.config.get('sha_{}'.format(_type), '') == sha_original:
                    self.print_debug('[*] _update_database the same hash for {}, skipping update'.format(_type))
                    progress_adder += int(100 / len(dict_files))
                    continue

                self.progressbar_update.setValue(25+progress_adder)
                self.progressbar_update.setStringPainted(True)

                downloaded_data = self._make_http_request_wrapper(url)
                if not downloaded_data:
                    return False
                
                hash_sha512 = hashlib.sha512()
                hash_sha512.update(downloaded_data)
                downloaded_sha = hash_sha512.hexdigest()

                if sha_original != downloaded_sha:
                    self.print_debug(
                        "[-] _update_database hash mismatch for {}, should be: {} is: {}".format(_type, sha_original,
                                                                                                 downloaded_sha))
                    return False

                try:
                    loaded_json = json.loads(downloaded_data)
                except:
                    self.print_debug(
                        "[-] _update_database cannot decode json for {}: {}".format(_type, traceback.format_exc()))
                    return False

                i = 0
                progress_adder += int(100 / progress_divider)
                json_length = len(loaded_json)
                for name in loaded_json:
                    bugs = []
                    i += 1
                    if i % 1000 == 0:
                        percent = int((i * 100. / json_length) / 4) + progress_adder
                        self.progressbar_update.setValue(percent)
                        self.progressbar_update.setStringPainted(True)
                    # No bugs
                    if len(loaded_json[name]['vulnerabilities']) == 0:
                        continue

                    for vulnerability in loaded_json[name]['vulnerabilities']:
                        bug = {'id': vulnerability['id'], 'title': vulnerability['title'].encode('utf-8'),
                               'vuln_type': vulnerability['vuln_type'].encode('utf-8'), 'reference': ''}

                        if 'references' in vulnerability:
                            if 'url' in vulnerability['references']:
                                references = []
                                for reference_url in vulnerability['references']['url']:
                                    references.append(reference_url.encode('utf-8'))
                                if len(references) != 0:
                                    bug['reference'] = references
                        if 'cve' in vulnerability:
                            bug['cve'] = vulnerability['cve'].encode('utf-8')
                        if 'exploitdb' in vulnerability:
                            bug['exploitdb'] = vulnerability['exploitdb'][0].encode('utf-8')
                        # Sometimes there is no fixed in or its None
                        if 'fixed_in' in vulnerability and vulnerability['fixed_in']:
                            bug['fixed_in'] = vulnerability['fixed_in'].encode('utf-8')
                        else:
                            bug['fixed_in'] = '0'
                        bugs.append(bug)
                    temp_database[name] = bugs

                progress_adder += int(100 / progress_divider)
                self.database[_type] = temp_database
                self.update_config('sha_{}'.format(_type), sha_original)
            except:
                self.print_debug("_update_database parser error for {}: {}".format(_type, traceback.format_exc()))
                return False

        return True

    def scan_type_check(self, messageInfo, as_thread):
        if as_thread:
            if self.config.get('scan_type', 1) == 1:
                threading.Thread(target=self.check_url_or_body, args=(messageInfo, "plugins",)).start()
                threading.Thread(target=self.check_url_or_body, args=(messageInfo, "themes",)).start()
            elif self.config.get('scan_type', 1) == 2:
                threading.Thread(target=self.check_url_or_body, args=(messageInfo, "plugins",)).start()
            elif self.config.get('scan_type', 1) == 3:
                threading.Thread(target=self.check_url_or_body, args=(messageInfo, "themes",)).start()
        else:
            issues = []
            if self.config.get('scan_type', 1) == 1:
                issues += self.check_url_or_body(messageInfo, "plugins")
                issues += (self.check_url_or_body(messageInfo, "themes") or [])
            elif self.config.get('scan_type', 1) == 2:
                issues += self.check_url_or_body(messageInfo, "plugins")
            elif self.config.get('scan_type', 1) == 3:
                issues += (self.check_url_or_body(messageInfo, "themes") or [])
            return issues

    # implement IScannerCheck
    def doPassiveScan(self, baseRequestResponse):
        return self.scan_type_check(baseRequestResponse, False)

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 1

    # implement IHttpListener
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.is_burp_pro or messageIsRequest:
            return

        # We are interested only with valid requests
        response = self.helpers.analyzeResponse(messageInfo.getResponse())
        if response.getStatusCode() not in INTERESTING_CODES:
            return

        if toolFlag == IBurpExtenderCallbacks.TOOL_PROXY:
            self.scan_type_check(messageInfo, True)

    def check_url_or_body(self, base_request_response, _type):
        if self.config.get('full_body', False):
            return self.check_body(base_request_response, _type)
        else:
            return self.check_url(base_request_response, _type)

    def check_url(self, base_request_response, _type):
        try:
            wp_content_pattern = bytearray(
                "{}/{}/".format(self.config.get('wp_content', 'wp-content'), _type))

            url = str(self.helpers.analyzeRequest(base_request_response).getUrl())
            wp_content_begin_in_url = self.helpers.indexOf(url, wp_content_pattern, True, 0, len(url))
            if wp_content_begin_in_url == -1:
                return []

            regexp_plugin_name = re.compile(
                "{}/{}/([A-Za-z0-9_-]+)".format(self.config.get('wp_content', 'wp-content'), _type), re.IGNORECASE)
            plugin_name_regexp = regexp_plugin_name.search(url)
            if plugin_name_regexp:
                current_domain_not_normalized = url[0:wp_content_begin_in_url]
                current_domain = self.normalize_url(current_domain_not_normalized)
                plugin_name = plugin_name_regexp.group(1).lower()

                if self.is_unique_plugin_on_website(current_domain, plugin_name):
                    version_type = 'active'
                    [version_number, version_request] = self.active_scan(current_domain_not_normalized, _type,
                                                                         plugin_name,
                                                                         base_request_response)

                    request = base_request_response.getRequest()
                    wp_content_begin = self.helpers.indexOf(request, wp_content_pattern, True, 0, len(request))
                    markers = [
                        array('i', [wp_content_begin, wp_content_begin + len(wp_content_pattern) + len(plugin_name)])]

                    if version_number == '0':
                        version_number_regexp = self.regexp_version_number.search(url)
                        if version_number_regexp:
                            version_number = version_number_regexp.group(1).rstrip(".")
                            version_type = 'passive'

                            version_number_begin = self.helpers.indexOf(request,
                                                                        self.helpers.stringToBytes(version_number),
                                                                        True, 0,
                                                                        len(request))
                            markers.append(
                                array('i', [version_number_begin, version_number_begin + len(version_number)]))

                    return self.is_vulnerable_plugin_version(self.callbacks.applyMarkers(base_request_response, markers, None),
                                                      _type, plugin_name, version_number, version_type, version_request)
        except:
            self.print_debug("[-] check_url error: {}".format(traceback.format_exc()))
            return []

    def check_body(self, base_request_response, _type):
        response = base_request_response.getResponse()
        wp_content_pattern = bytearray(
            "{}/{}/".format(self.config.get('wp_content', 'wp-content'), _type))
        matches = self.find_pattern_in_data(response, wp_content_pattern)
        if not matches:
            return []

        url = str(self.helpers.analyzeRequest(base_request_response).getUrl())
        current_domain = self.normalize_url(url)

        regexp_plugin_name = re.compile(
            "{}/{}/([A-Za-z0-9_-]+)".format(self.config.get('wp_content', 'wp-content'), _type), re.IGNORECASE)

        issues = []
        for wp_content_start, wp_content_stop in matches:
            # For performance reason only part of reponse
            response_partial_after = self.helpers.bytesToString(
                self.array_slice_bytes(response, wp_content_start, wp_content_stop + 100))

            plugin_name_regexp = regexp_plugin_name.search(response_partial_after)
            if plugin_name_regexp:
                plugin_name = plugin_name_regexp.group(1).lower()
                if self.is_unique_plugin_on_website(current_domain, plugin_name):
                    response_partial_before = self.helpers.bytesToString(
                        self.array_slice_bytes(response, wp_content_start - 100, wp_content_start)).lower()

                    markers = [array('i', [wp_content_start, wp_content_stop + len(plugin_name)])]

                    version_type = 'active'
                    version_number = '0'
                    version_request = None

                    url_begin_index = response_partial_before.rfind('http://')
                    if url_begin_index == -1:
                        url_begin_index = response_partial_before.rfind('https://')
                    if url_begin_index == -1:
                        url_begin_index = response_partial_before.rfind('//')

                    if url_begin_index != -1:
                        [version_number, version_request] = self.active_scan(
                            response_partial_before[url_begin_index:],
                            _type, plugin_name, base_request_response)

                    if version_number == '0':
                        # https://stackoverflow.com/questions/30020184/how-to-find-the-first-index-of-any-of-a-set-of-characters-in-a-string
                        url_end_index = next(
                            (i for i, ch in enumerate(response_partial_after) if ch in {"'", "\"", ")"}),
                            None)
                        if url_end_index:

                            url_end = response_partial_after[0:url_end_index]
                            version_number_regexp = self.regexp_version_number.search(url_end)
                            if version_number_regexp:
                                version_number = version_number_regexp.group(1).rstrip(".")
                                version_type = 'passive'

                                version_marker_start = url_end.find(version_number)
                                markers.append(array('i', [wp_content_start + version_marker_start,
                                                           wp_content_start + version_marker_start + len(
                                                               version_number)]))

                    issues += self.is_vulnerable_plugin_version(self.callbacks.applyMarkers(base_request_response, None, markers),
                                                      _type, plugin_name, version_number, version_type, version_request)

        return issues
    def find_pattern_in_data(self, data, pattern):
        matches = []
        start = 0
        data_length = len(data)
        pattern_length = len(pattern)
        while start < data_length:
            # indexOf(byte[] data, byte[] pattern, boolean caseSensitive, int from, int to)
            start = self.helpers.indexOf(data, pattern, False, start, data_length)
            if start == -1:
                break
            matches.append(array('i', [start, start + pattern_length]))
            start += pattern_length

        return matches

    def array_slice_bytes(self, _bytes, start, stop):
        byte_length = len(_bytes)
        if stop > byte_length:
            stop = byte_length
        if start < 0:
            start = 0

        temp = []
        for i in xrange(start, stop):
            temp.append(_bytes[i])
        return array('b', temp)

    def normalize_url(self, url):
        parsed_url = urlparse.urlparse(url)
        current_domain = parsed_url.netloc
        # Domain may looks like www.sth.pl:80, so here we normalize this
        if current_domain.startswith('www.'):
            current_domain = current_domain[4:]
        if ":" in current_domain:
            current_domain = current_domain.split(":")[0]
        self.print_debug("[*] normalize_url before: {}, after: {}".format(url, current_domain))
        return current_domain

    def add_issue_wrapper(self, issue):
        self.lock_issues.acquire()
        row = self.list_issues.size()
        self.list_issues.add(issue)
        self.table_issues.fireTableRowsInserted(row, row)
        self.lock_issues.release()
        return issue

    def active_scan(self, current_domain, _type, plugin_name, base_request_response):
        current_version = '0'
        readme_http_request = None
        markers = None

        if self.config.get('active_scan', False):
            url = str(self.helpers.analyzeRequest(base_request_response).getUrl()).lower()
            self.print_debug("Current domain: {}, URL: {}".format(current_domain, url))
            if current_domain.startswith('//'):
                if url.startswith('http://'):
                    current_domain = 'http://' + current_domain[2:]
                else:
                    current_domain = 'https://' + current_domain[2:]
            elif not current_domain.startswith('http'):
                if url.startswith('http://'):
                    current_domain = 'http://' + current_domain
                else:
                    current_domain = 'https://' + current_domain

            readme_url = "{}{}/{}/{}/readme.txt".format(current_domain, self.config.get('wp_content', 'wp-content'),
                                                        _type, plugin_name)

            self.print_debug("[*] active_scan readme_url: {}".format(readme_url))
            try:
                if url.endswith('readme.txt'):
                    # This might be potential recursion, so don't make another request here
                    return ['0', None]

                readme_request = self.helpers.buildHttpRequest(URL(readme_url))
                readme_http_request = self.callbacks.makeHttpRequest(base_request_response.getHttpService(),
                                                                     readme_request)
                readme_response = readme_http_request.getResponse()

                readme_response_info = self.helpers.analyzeResponse(readme_response)

                if readme_response_info.getStatusCode() in INTERESTING_CODES:
                    # Idea from wpscan\lib\common\models\wp_item\versionable.rb
                    readme_content = self.helpers.bytesToString(readme_response)
                    regexp_stable_tag = self.regexp_stable_tag.search(readme_content)

                    if regexp_stable_tag:
                        stable_tag = regexp_stable_tag.group(1)
                        current_version = stable_tag
                        markers = [array('i', [regexp_stable_tag.start(1), regexp_stable_tag.end(1)])]
                        self.print_debug("[*] active_scan stable tag: {}".format(stable_tag))

                    changelog_regexp = self.regexp_version_from_changelog.finditer(readme_content)
                    for version_match in changelog_regexp:
                        version = version_match.group(1)
                        if LooseVersion(version) > LooseVersion(current_version):
                            self.print_debug("[*] active_scan newer version: {}".format(version))
                            current_version = version
                            markers = [array('i', [version_match.start(1), version_match.end(1)])]

                if markers:
                    readme_http_request = self.callbacks.applyMarkers(readme_http_request, None, markers)
            except:
                self.print_debug(
                    "[-] active_scan for {} error: {}".format(readme_url, traceback.format_exc()))
                return ['0', None]
        return [current_version, readme_http_request]

    def is_unique_plugin_on_website(self, url, plugin_name):
        if plugin_name not in self.list_plugins_on_website[url]:
            self.list_plugins_on_website[url].append(plugin_name)
            self.print_debug("[+] is_unique_plugin_on_website URL: {}, plugin: {}".format(url, plugin_name))
            return True

        return False

    def parse_bug_details(self, bug, plugin_name, _type):
        content = "ID: <a href='https://wpvulndb.com/vulnerabilities/{}'>{}</a><br />Title: {}<br />Type: {}<br />".format(
            bug['id'], bug['id'], bug['title'], bug['vuln_type'])
        if 'reference' in bug:
            content += "References:<br />"
            for reference in bug['reference']:
                content += "<a href='{}'>{}</a><br />".format(reference, reference)
        if 'cve' in bug:
            content += "CVE: {}<br />".format(bug['cve'])
        if 'exploitdb' in bug:
            content += "Exploit Database: <a href='https://www.exploit-db.com/exploits/{}/'>{}</a><br />".format(
                bug['exploitdb'], bug['exploitdb'])
        if 'fixed_in' in bug:
            content += "Fixed in version: {}<br />".format(bug['fixed_in'])
        content += "WordPress URL: <a href='https://wordpress.org/{type}/{plugin_name}'>https://wordpress.org/{type}/{plugin_name}</a>".format(
            type=_type, plugin_name=plugin_name)
        return content

    def is_vulnerable_plugin_version(self, base_request_response, _type, plugin_name, version_number, version_type,
                                     version_request):
        has_vuln = False
        issues = []
        if version_type == 'active' and version_number != '0':
            requests = [base_request_response, version_request]
        else:
            requests = [base_request_response]

        url = self.helpers.analyzeRequest(base_request_response).getUrl()

        if plugin_name in self.database[_type]:
            self.print_debug(
                "[*] is_vulnerable_plugin_version check {} {} version {}".format(_type, plugin_name, version_number))
            for bug in self.database[_type][plugin_name]:
                if bug['fixed_in'] == '0' or (
                                version_number != '0' and LooseVersion(version_number) < LooseVersion(bug['fixed_in'])):
                    self.print_debug(
                        "[+] is_vulnerable_plugin_version vulnerability inside {} version {}".format(plugin_name,
                                                                                                     version_number))
                    has_vuln = True
                    issues.append(self.add_issue_wrapper(CustomScanIssue(
                        url,
                        requests,
                        "{} inside {} {} version {}".format(bug['vuln_type'], _type[:-1], plugin_name, version_number),
                        self.parse_bug_details(bug, plugin_name, _type),
                        "High", "Certain" if version_type == 'active' else "Firm")))
                elif self.config.get('all_vulns', False):
                    self.print_debug(
                        "[+] is_vulnerable_plugin_version potential vulnerability inside {} version {}".format(
                            plugin_name, version_number))
                    has_vuln = True
                    issues.append(self.add_issue_wrapper(CustomScanIssue(
                        url,
                        requests,
                        "Potential {} inside {} {} fixed in {}".format(bug['vuln_type'], _type[:-1], plugin_name,
                                                                       bug['fixed_in']),
                        self.parse_bug_details(bug, plugin_name, _type),
                        "Information", "Certain")))

        if not has_vuln and self.config.get('print_info', False):
            print_info_details = "Found {} {}".format(_type[:-1], plugin_name)
            if version_number != '0':
                print_info_details += " version {}".format(version_number)
            self.print_debug("[+] is_vulnerable_plugin_version print info: {}".format(print_info_details))
            issues.append(self.add_issue_wrapper(CustomScanIssue(
                url,
                requests,
                print_info_details,
                "{}<br /><a href='https://wordpress.org/{type}/{plugin_name}'>https://wordpress.org/{type}/{plugin_name}</a>".format(
                    print_info_details, type=_type, plugin_name=plugin_name),
                "Information", "Certain" if version_type == 'active' and version_number != '0' else "Firm")))

        return issues

    def createMenuItems(self, invocation):
        return [JMenuItem("Send to WordPress Scanner Intruder",
                          actionPerformed=lambda x, inv=invocation: self.menu_send_to_intruder_on_click(inv))]

    def menu_send_to_intruder_on_click(self, invocation):
        response = invocation.getSelectedMessages()[0]
        http_service = response.getHttpService()
        request = response.getRequest()
        analyzed_request = self.helpers.analyzeRequest(response)

        for param in analyzed_request.getParameters():
            # Remove all POST and GET parameters
            if param.getType() == IParameter.PARAM_COOKIE:
                continue
            request = self.helpers.removeParameter(request, param)

        # Convert to GET
        is_post = self.helpers.indexOf(request, bytearray("POST"), True, 0, 4)
        if is_post != -1:
            request = self.helpers.toggleRequestMethod(request)

        # Add backslash to last part of url
        url = str(analyzed_request.getUrl())
        if not url.endswith("/"):
            request_string = self.helpers.bytesToString(request)
            # We are finding HTTP version protocol
            http_index = request_string.find(" HTTP")
            new_request_string = request_string[0:http_index] + "/" + request_string[http_index:]
            request = self.helpers.stringToBytes(new_request_string)

        http_index_new_request = self.helpers.indexOf(request, bytearray(" HTTP"), True, 0, len(request))
        matches = [array('i', [http_index_new_request, http_index_new_request])]

        self.callbacks.sendToIntruder(http_service.getHost(), http_service.getPort(),
                                      True if http_service.getProtocol() == "https" else False, request, matches)

    # implement IMessageEditorController
    def getHttpService(self):
        return self._current_advisory_entry.getHttpService()

    def getRequest(self):
        return self._current_advisory_entry.getRequest()

    def getResponse(self):
        return self._current_advisory_entry.getResponse()

    # implement ITab
    def getTabCaption(self):
        return "WordPress Scanner"

    def getUiComponent(self):
        return self.panel_main


class CustomScanIssue(IScanIssue):
    def __init__(self, url, http_messages, name, detail, severity, confidence):
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        # High, Medium, Low, Information, False positive
        self._severity = severity
        # Certain, Firm, Tentative
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self.getHttpMessages()[0].getHttpService()

    def getRequest(self, number):
        if len(self._http_messages) > number:
            return self._http_messages[number].getRequest()
        else:
            return ""

    def getResponse(self, number):
        if len(self._http_messages) > number:
            return self._http_messages[number].getResponse()
        else:
            return ""

    def getHost(self):
        host = "{}://{}".format(self.getHttpService().getProtocol(), self.getHttpService().getHost())
        port = self.getHttpService().getPort()
        if port not in [80, 443]:
            host += ":{}".format(port)
        return host

    def getPath(self):
        url = str(self.getUrl())
        spliced = url.split("/")
        return "/" + "/".join(spliced[3:])


class IssuesDetailsTable(JTable):
    def __init__(self, extender, model):
        self._extender = extender
        self.setModel(model)

    def changeSelection(self, row, col, toggle, extend):
        model_row = self.convertRowIndexToModel(row)
        self.current_issue = self._extender.list_issues.get(model_row)

        issue_details = self.current_issue.getIssueDetail()
        self._extender.panel_bottom_advisory.setText(issue_details)
        self._extender.panel_bottom_request1.setMessage(self.current_issue.getRequest(0), True)
        self._extender.panel_bottom_response1.setMessage(self.current_issue.getResponse(0), False)

        request2 = self.current_issue.getRequest(1)
        if request2 != "":
            self._extender.panel_bottom.setEnabledAt(3, True)
            self._extender.panel_bottom.setEnabledAt(4, True)
            self._extender.panel_bottom_request2.setMessage(request2, True)
            self._extender.panel_bottom_response2.setMessage(self.current_issue.getResponse(1), False)
        else:
            self._extender.panel_bottom.setEnabledAt(3, False)
            self._extender.panel_bottom.setEnabledAt(4, False)

        JTable.changeSelection(self, row, col, toggle, extend)


class IssuesTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender

    def getRowCount(self):
        try:
            return self._extender.list_issues.size()
        except:
            return 0

    def getColumnCount(self):
        return 5

    def getColumnName(self, column_index):
        if column_index == 0:
            return "Issue type"
        elif column_index == 1:
            return "Host"
        elif column_index == 2:
            return "Path"
        elif column_index == 3:
            return "Severity"
        elif column_index == 4:
            return "Confidence"

    def getValueAt(self, row_index, column_index):
        advisory_entry = self._extender.list_issues.get(row_index)
        if column_index == 0:
            return advisory_entry.getIssueName()
        elif column_index == 1:
            return advisory_entry.getHost()
        elif column_index == 2:
            return advisory_entry.getPath()
        elif column_index == 3:
            return advisory_entry.getSeverity()
        elif column_index == 4:
            return advisory_entry.getConfidence()


class IntruderPluginsGenerator(IIntruderPayloadGeneratorFactory):
    def __init__(self, generator):
        self.generator = generator

    def getGeneratorName(self):
        return "WordPress Plugins"

    def createNewInstance(self, attack):
        return IntruderPayloadGenerator(self.generator, "plugins")


class IntruderThemesGenerator(IIntruderPayloadGeneratorFactory):
    def __init__(self, generator):
        self.generator = generator

    def getGeneratorName(self):
        return "WordPress Themes"

    def createNewInstance(self, attack):
        return IntruderPayloadGenerator(self.generator, "themes")


class IntruderPluginsThemesGenerator(IIntruderPayloadGeneratorFactory):
    def __init__(self, generator):
        self.generator = generator

    def getGeneratorName(self):
        return "WordPress Plugins and Themes"

    def createNewInstance(self, attack):
        return IntruderPayloadGeneratorMixed(self.generator)


class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender, _type):
        self.payload_index = 0
        self.extender = extender
        self.type = _type
        self.iterator = self.extender.database[self.type].iteritems()
        self.iterator_length = len(self.extender.database[self.type])
        self.extender.print_debug("[+] Start intruder for {}, has {} payloads".format(self.type, self.iterator_length))

    def hasMorePayloads(self):
        return self.payload_index < self.iterator_length

    def getNextPayload(self, base_value):
        if self.payload_index <= self.iterator_length:
            try:
                k, v = self.iterator.next()
                self.payload_index += 1
                return "{}/{}/{}/".format(self.extender.config.get('wp_content', 'wp-content'), self.type, k)

            except StopIteration:
                pass

    def reset(self):
        self.payload_index = 0


class IntruderPayloadGeneratorMixed(IIntruderPayloadGenerator):
    def __init__(self, extender):
        self.payload_index = 0
        self.extender = extender
        self.iterator = chain(self.extender.database["themes"].iteritems(),
                              self.extender.database["plugins"].iteritems())
        self.iterator_themes_length = len(self.extender.database["themes"])
        self.iterator_length = (self.iterator_themes_length + len(self.extender.database["plugins"]))
        self.extender.print_debug("[+] Start mixed intruder, has {} payloads".format(self.iterator_length))

    def hasMorePayloads(self):
        return self.payload_index <= self.iterator_length

    def getNextPayload(self, base_value):
        if self.payload_index < self.iterator_length:
            try:
                k, v = self.iterator.next()
                self.payload_index += 1

                if self.payload_index <= self.iterator_themes_length:
                    return "{}/{}/{}/".format(self.extender.config.get('wp_content', 'wp-content'), "themes", k)
                else:
                    return "{}/{}/{}/".format(self.extender.config.get('wp_content', 'wp-content'), "plugins", k)
            except StopIteration:
                pass

    def reset(self):
        self.payload_index = 0
