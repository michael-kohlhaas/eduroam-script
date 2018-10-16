#!/usr/bin/env bash
if [ -z "$BASH" ] ; then
   bash  $0
   exit
fi



my_name=$0


function setup_environment {
  bf=""
  n=""
  ORGANISATION="BildungsCentrum der Wirtschaft gemeinnützige GmbH (FOM, eufom, GoBS, VWA, BA, BCW, iom)"
  URL="ihre lokale eduroam Informations-Webseite"
  SUPPORT="eduroam@bcw-gruppe.de"
if [ ! -z "$DISPLAY" ] ; then
  if which zenity 1>/dev/null 2>&1 ; then
    ZENITY=`which zenity`
  elif which kdialog 1>/dev/null 2>&1 ; then
    KDIALOG=`which kdialog`
  else
    if tty > /dev/null 2>&1 ; then
      if  echo $TERM | grep -E -q "xterm|gnome-terminal|lxterminal"  ; then
        bf="[1m";
        n="[0m";
      fi
    else
      find_xterm
      if [ -n "$XT" ] ; then
        $XT -e $my_name
      fi
    fi
  fi
fi
}

function split_line {
echo $1 | awk  -F '\\\\n' 'END {  for(i=1; i <= NF; i++) print $i }'
}

function find_xterm {
terms="xterm aterm wterm lxterminal rxvt gnome-terminal konsole"
for t in $terms
do
  if which $t > /dev/null 2>&1 ; then
  XT=$t
  break
  fi
done
}


function ask {
     T="DFN eduroam CAT"
#  if ! [ -z "$3" ] ; then
#     T="$T: $3"
#  fi
  if [ ! -z $KDIALOG ] ; then
     if $KDIALOG --yesno "${1}\n${2}?" --title "$T" ; then
       return 0
     else
       return 1
     fi
  fi
  if [ ! -z $ZENITY ] ; then
     text=`echo "${1}" | fmt -w60`
     if $ZENITY --no-wrap --question --text="${text}\n${2}?" --title="$T" 2>/dev/null ; then
       return 0
     else
       return 1
     fi
  fi

  yes=J
  no=N
  yes1=`echo $yes | awk '{ print toupper($0) }'`
  no1=`echo $no | awk '{ print toupper($0) }'`

  if [ $3 == "0" ]; then
    def=$yes
  else
    def=$no
  fi

  echo "";
  while true
  do
  split_line "$1"
  read -p "${bf}$2 ${yes}/${no}? [${def}]:$n " answer
  if [ -z "$answer" ] ; then
    answer=${def}
  fi
  answer=`echo $answer | awk '{ print toupper($0) }'`
  case "$answer" in
    ${yes1})
       return 0
       ;;
    ${no1})
       return 1
       ;;
  esac
  done
}

function alert {
  if [ ! -z $KDIALOG ] ; then
     $KDIALOG --sorry "${1}"
     return
  fi
  if [ ! -z $ZENITY ] ; then
     $ZENITY --warning --text="$1" 2>/dev/null
     return
  fi
  echo "$1"

}

function show_info {
  if [ ! -z $KDIALOG ] ; then
     $KDIALOG --msgbox "${1}"
     return
  fi
  if [ ! -z $ZENITY ] ; then
     $ZENITY --info --width=500 --text="$1" 2>/dev/null
     return
  fi
  split_line "$1"
}

function confirm_exit {
  if [ ! -z $KDIALOG ] ; then
     if $KDIALOG --yesno "Wirklich beenden?"  ; then
     exit 1
     fi
  fi
  if [ ! -z $ZENITY ] ; then
     if $ZENITY --question --text="Wirklich beenden?" 2>/dev/null ; then
        exit 1
     fi
  fi
}



function prompt_nonempty_string {
  prompt=$2
  if [ ! -z $ZENITY ] ; then
    if [ $1 -eq 0 ] ; then
     H="--hide-text "
    fi
    if ! [ -z "$3" ] ; then
     D="--entry-text=$3"
    fi
  elif [ ! -z $KDIALOG ] ; then
    if [ $1 -eq 0 ] ; then
     H="--password"
    else
     H="--inputbox"
    fi
  fi


  out_s="";
  if [ ! -z $ZENITY ] ; then
    while [ ! "$out_s" ] ; do
      out_s=`$ZENITY --entry --width=300 $H $D --text "$prompt" 2>/dev/null`
      if [ $? -ne 0 ] ; then
        confirm_exit
      fi
    done
  elif [ ! -z $KDIALOG ] ; then
    while [ ! "$out_s" ] ; do
      out_s=`$KDIALOG $H "$prompt" "$3"`
      if [ $? -ne 0 ] ; then
        confirm_exit
      fi
    done  
  else
    while [ ! "$out_s" ] ; do
      read -p "${prompt}: " out_s
    done
  fi
  echo "$out_s";
}

function user_cred {
  PASSWORD="a"
  PASSWORD1="b"

  if ! USER_NAME=`prompt_nonempty_string 1 "Geben Sie ihre Benutzerkennung ein"` ; then
    exit 1
  fi

  while [ "$PASSWORD" != "$PASSWORD1" ]
  do
    if ! PASSWORD=`prompt_nonempty_string 0 "Geben Sie ihr Passwort ein"` ; then
      exit 1
    fi
    if ! PASSWORD1=`prompt_nonempty_string 0 "Wiederholen Sie das Passwort"` ; then
      exit 1
    fi
    if [ "$PASSWORD" != "$PASSWORD1" ] ; then
      alert "Die Passwörter stimmen nicht überein"
    fi
  done
}
setup_environment
show_info "Dieses Installationsprogramm wurde für ${ORGANISATION} hergestellt.\n\nMehr Informationen und Kommentare:\n\nEMAIL: ${SUPPORT}\nWWW: ${URL}\n\nDas Installationsprogramm wurde mit Software vom GEANT Projekt erstellt."
if ! ask "Dieses Installationsprogramm funktioniert nur für Anwender von ${bf}BildungsCentrum der Wirtschaft gemeinnützige GmbH (FOM, eufom, GoBS, VWA, BA, BCW, iom).${n}" "Weiter" 1 ; then exit; fi
if [ -d $HOME/.cat_installer ] ; then
   if ! ask "Das Verzeichnis $HOME/.cat_installer existiert bereits; einige Dateien darin könnten überschrieben werden." "Weiter" 1 ; then exit; fi
else
  mkdir $HOME/.cat_installer
fi
# save certificates
echo "-----BEGIN CERTIFICATE-----
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
MAR0BaysLeMIF6+G3o3HjtrZ
-----END CERTIFICATE-----

" > $HOME/.cat_installer/ca.pem
function run_python_script {
PASSWORD=$( echo "$PASSWORD" | sed "s/'/\\\'/g" )
if python << EEE1 > /dev/null 2>&1
import dbus
EEE1
then
    PYTHON=python
elif python3 << EEE2 > /dev/null 2>&1
import dbus
EEE2
then
    PYTHON=python3
else
    PYTHON=none
    return 1
fi

$PYTHON << EOF > /dev/null 2>&1
#-*- coding: utf-8 -*-
import dbus
import re
import sys
import uuid
import os

class EduroamNMConfigTool:

    def connect_to_NM(self):
        #connect to DBus
        try:
            self.bus = dbus.SystemBus()
        except dbus.exceptions.DBusException:
            print("Can't connect to DBus")
            sys.exit(2)
        #main service name
        self.system_service_name = "org.freedesktop.NetworkManager"
        #check NM version
        self.check_nm_version()
        if self.nm_version == "0.9" or self.nm_version == "1.0":
            self.settings_service_name = self.system_service_name
            self.connection_interface_name = "org.freedesktop.NetworkManager.Settings.Connection"
            #settings proxy
            sysproxy = self.bus.get_object(self.settings_service_name, "/org/freedesktop/NetworkManager/Settings")
            #settings intrface
            self.settings = dbus.Interface(sysproxy, "org.freedesktop.NetworkManager.Settings")
        elif self.nm_version == "0.8":
            #self.settings_service_name = "org.freedesktop.NetworkManagerUserSettings"
            self.settings_service_name = "org.freedesktop.NetworkManager"
            self.connection_interface_name = "org.freedesktop.NetworkManagerSettings.Connection"
            #settings proxy
            sysproxy = self.bus.get_object(self.settings_service_name, "/org/freedesktop/NetworkManagerSettings")
            #settings intrface
            self.settings = dbus.Interface(sysproxy, "org.freedesktop.NetworkManagerSettings")
        else:
            print("This Network Manager version is not supported")
            sys.exit(2)

    def check_opts(self):
        self.cacert_file = '${HOME}/.cat_installer/ca.pem'
        self.pfx_file = '${HOME}/.cat_installer/user.p12'
        if not os.path.isfile(self.cacert_file):
            print("Certificate file not found, looks like a CAT error")
            sys.exit(2)

    def check_nm_version(self):
        try:
            proxy = self.bus.get_object(self.system_service_name, "/org/freedesktop/NetworkManager")
            props = dbus.Interface(proxy, "org.freedesktop.DBus.Properties")
            version = props.Get("org.freedesktop.NetworkManager", "Version")
        except dbus.exceptions.DBusException:
            version = "0.8"
        if re.match(r'^1\.', version):
            self.nm_version = "1.0"
            return
        if re.match(r'^0\.9', version):
            self.nm_version = "0.9"
            return
        if re.match(r'^0\.8', version):
            self.nm_version = "0.8"
            return
        else:
            self.nm_version = "Unknown version"
            return

    def byte_to_string(self, barray):
        return "".join([chr(x) for x in barray])


    def delete_existing_connections(self, ssid):
        "checks and deletes earlier connections"
        try:
            conns = self.settings.ListConnections()
        except dbus.exceptions.DBusException:
            print("DBus connection problem, a sudo might help")
            exit(3)
        for each in conns:
            con_proxy = self.bus.get_object(self.system_service_name, each)
            connection = dbus.Interface(con_proxy, "org.freedesktop.NetworkManager.Settings.Connection")
            try:
               connection_settings = connection.GetSettings()
               if connection_settings['connection']['type'] == '802-11-wireless':
                   conn_ssid = self.byte_to_string(connection_settings['802-11-wireless']['ssid'])
                   if conn_ssid == ssid:
                       connection.Delete()
            except dbus.exceptions.DBusException:
               pass

    def add_connection(self,ssid):
        server_alt_subject_name_list = dbus.Array({'DNS:radius-eduroam.bcw-gruppe.de'})
        server_name = 'radius-eduroam.bcw-gruppe.de'
        if self.nm_version == "0.9" or self.nm_version == "1.0":
             match_key = 'altsubject-matches'
             match_value = server_alt_subject_name_list
        else:
             match_key = 'subject-match'
             match_value = server_name
            
        s_con = dbus.Dictionary({
            'type': '802-11-wireless',
            'uuid': str(uuid.uuid4()),
            'permissions': ['user:$USER'],
            'id': ssid 
        })
        s_wifi = dbus.Dictionary({
            'ssid': dbus.ByteArray(ssid.encode('utf8')),
            'security': '802-11-wireless-security'
        })
        s_wsec = dbus.Dictionary({
            'key-mgmt': 'wpa-eap',
            'proto': ['rsn',],
            'pairwise': ['ccmp',],
            'group': ['ccmp', 'tkip']
        })
        s_8021x = dbus.Dictionary({
            'eap': ['ttls'],
            'identity': '$USER_NAME',
            'ca-cert': dbus.ByteArray("file://{0}\0".format(self.cacert_file).encode('utf8')),
             match_key: match_value,
            'password': '$PASSWORD',
            'phase2-auth': 'mschapv2',
            'anonymous-identity': 'anonymous@bcw-gruppe.de',
        })
        s_ip4 = dbus.Dictionary({'method': 'auto'})
        s_ip6 = dbus.Dictionary({'method': 'auto'})
        con = dbus.Dictionary({
            'connection': s_con,
            '802-11-wireless': s_wifi,
            '802-11-wireless-security': s_wsec,
            '802-1x': s_8021x,
            'ipv4': s_ip4,
            'ipv6': s_ip6
        })
        self.settings.AddConnection(con)

    def main(self):
        self.check_opts()
        ver = self.connect_to_NM()
        self.delete_existing_connections('eduroam')
        self.add_connection('eduroam')

if __name__ == "__main__":
    ENMCT = EduroamNMConfigTool()
    ENMCT.main()
EOF
}
function create_wpa_conf {
cat << EOFW >> $HOME/.cat_installer/cat_installer.conf

network={
  ssid="eduroam"
  key_mgmt=WPA-EAP
  pairwise=CCMP
  group=CCMP TKIP
  eap=TTLS
  ca_cert="${HOME}/.cat_installer/ca.pem"
  identity="${USER_NAME}"
  domain_suffix_match="radius-eduroam.bcw-gruppe.de"
  phase2="auth=MSCHAPV2"
  password="${PASSWORD}"
  anonymous_identity="anonymous@bcw-gruppe.de"
}
EOFW
chmod 600 $HOME/.cat_installer/cat_installer.conf
}
#prompt user for credentials
  user_cred
  if run_python_script ; then
   show_info "Installation erfolgreich"
else
   show_info "Konfiguration von NetworkManager fehlgeschlagen, erzeuge nun wpa_supplicant.conf Datei"
   if ! ask "Network Manager configuration failed, but we may generate a wpa_supplicant configuration file if you wish. Be warned that your connection password will be saved in this file as clear text." "Datei schreiben" 1 ; then exit ; fi

if [ -f $HOME/.cat_installer/cat_installer.conf ] ; then
  if ! ask "Datei $HOME/.cat_installer/cat_installer.conf existiert bereits, sie wird überschrieben." "Weiter" 1 ; then confirm_exit; fi
  rm $HOME/.cat_installer/cat_installer.conf
  fi
   create_wpa_conf
   show_info "Ausgabe nach $HOME/.cat_installer/cat_installer.conf geschrieben"
fi
