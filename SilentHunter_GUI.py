#SilentHunter_GUI.py
class color_controler():
    def __init__(self):
        self.colors = [
            '\033[91m', #RED
            '\033[92m', #GREEN
            '\033[93m', #YELOW
            '\033[94m', #BLUE
            '\033[95m', #MAGENTA
            '\033[96m', #CYAN
            '\033[97m', #WHITE
            '\033[0m'   #RESET
        ]
    def set_color(self, text):
        global title
        patern = [
        ["!", title, "▒", "WARNING", 'OFF', 'False'],
        ["+", "codes list", 'REMOVED', 'default', 'ON', 'True'],
        ['ID', 'network adapters', 'BSSID', 'WIFI', 'MAC', 'IP', 'STOPPED', "credit", "help", "show_MAC", "show_IP", 'MAC_spoofing', "IP_spoofing", 'wifi_cracking', 'name_spoofing', 'end', 'exit', 'stop', 'back', 'clear', 'start', 'menu'],
        ["╟", "╢"],
        [],
        ["Mr_DarkFear", "─", "│", "┘", "└", "┌", "┐", "╭", "╮", "╰", "╯", "┬", "┝", '*']
        ]
        result = text
        for i in patern:
            for i2 in i:
                result = result.replace(i2, self.colors[patern.index(i)]+ i2 + self.colors[7])
        return result

ColorControler = color_controler()

def c_print(text):
    global ColorControler
    print(ColorControler.set_color(text))

title = """
                                                            
   ▄▄▄▄       ██     ▄▄▄▄                                   
 ▄█▀▀▀▀█      ▀▀     ▀▀██                            ██     
 ██▄        ████       ██       ▄████▄   ██▄████▄  ███████  
  ▀████▄      ██       ██      ██▄▄▄▄██  ██▀   ██    ██     
      ▀██     ██       ██      ██▀▀▀▀▀▀  ██    ██    ██     
 █▄▄▄▄▄█▀  ▄▄▄██▄▄▄    ██▄▄▄   ▀██▄▄▄▄█  ██    ██    ██▄▄▄  
  ▀▀▀▀▀    ▀▀▀▀▀▀▀▀     ▀▀▀▀     ▀▀▀▀▀   ▀▀    ▀▀     ▀▀▀▀                                                             
 ▄▄                                                         
 ██                              ██                         
 ██▄████▄  ██    ██  ██▄████▄  ███████    ▄████▄    ██▄████ 
 ██▀   ██  ██    ██  ██▀   ██    ██      ██▄▄▄▄██   ██▀     
 ██    ██  ██    ██  ██    ██    ██      ██▀▀▀▀▀▀   ██      
 ██    ██  ██▄▄▄███  ██    ██    ██▄▄▄   ▀██▄▄▄▄█   ██      
 ▀▀    ▀▀   ▀▀▀▀ ▀▀  ▀▀    ▀▀     ▀▀▀▀     ▀▀▀▀▀    ▀▀      
                                                            
                                                                                                                                                                                                                                                                                                                                                                                                                    
"""