######################################################
#                name: yara_check.py
#                Creation date: 12 April 2018
#                purpose: Collect many yara rule files and
#                         run them against possibly malicious files
#                Author: Adam LeTang (Moros)
#                Version: 0.0.3a
#                ChangeLog:
#                   1.  13 april 2018 - Moros - 
#			- Fixed an error where running all rule files at once
#                         would cause Yara to crash with too many matches
#                       - Fixed logic a problem where running yara against multiple files would only
#                         return the last file ran
#                       - Fixed logic problem that kept the levels from printing in the right order
#	            2. 14 April 2018 - Moros - 
#                        - created html build system.
#                   3. 15 April 2018 - Moros -
#                        - added reset functionality
#                        - Added daemon functionality
#                        - Fixed logic problem to make matching more efficent
#                ToDo:
#                   1.  Implement some kind of multi threading to make it 
#                       even faster
#                   2.  Create a rule updater that will reach out someplace and get all the new rules
#                   3.  Website is very simple, make it better.
#		    5.  Create documentations
#       
#                Bugs:
#                   1. 13 april 2018 - moros - The fix didnt totally do it, sometimes it still crashes
#                      on to many matches troubleshooting....for now fixed with an exception.  
#	
#           	       seems it may be because of poorly written rules, i rewrote the one that
#                      seems to hit alot and that looks like its helping.
#
#                      Hmm...not sure waht i fucked up, but it seems to be picking everything
#                      up on base64 detection....and nothing else, need to figure out why.
#                      -  Tried running this on ghost, it picked everything else up
#                         including base64, might be a bad rule....
###########################################

import yara
import os
import sys
from datetime import datetime
import argparse
from time import time, sleep
import hashlib
from shutil import copyfile, move

#defaults
verbose = False
auto_open = False
errors = False
daemon_mode = False

#globals
errorlog = "logs/errors"

def reset():
   print "reseting to defaults"
   for root, dirs, files in os.walk(os.path.abspath('html/')):
      for html_file in files:
         os.remove('%s/%s' %(root,html_file))
   input = raw_input("Do you want to delete the malware from malware/? \n did you back it up? \n (yes/no)>> ")
   if input.lower() == 'yes':
      for root, dirs, files in os.walk(os.path.abspath('malware/')):
         for malware_file in files:
            os.remove('%s/%s' %(root,malware_file))
      print "all malware files removed"
   copyfile('backup/index.html', 'html/index.html') 
   print "all html files removed"
   sys.exit()

def getfilehash(file):
   BLOCKSIZE = 65536
   hasher = hashlib.sha1()
   with open(file, 'rb') as afile:
      buf = afile.read(BLOCKSIZE)
      while len(buf) > 0:
         hasher.update(buf)
         buf = afile.read(BLOCKSIZE)
   return str(hasher.hexdigest())



####
#
# This should work, Need to update it based on the <severity> level Possibly adding color? 
# right now it is based on the date.
#
####
def makehtml(data, file, hash, severity):
   if isinstance(data, (int, long)):
      rule = "no hits"
   else:
      rule = data.rule
   if severity == 0:
      bg_color = "green"
   elif severity == 1:
      bg_color = "red"
   elif severity == 2:
      bg_color = "orange"
   elif severity == 3:
      bg_color = "yellow"
   elif severity == 4:
      bg_color = "blue"
   elif severity == 5:
      bg_color = "aqua"
   else:
      bg_color = "brown"
   html_files = []
   date = datetime.now().strftime("%y-%m-%d %H:%M")
   for root, dirs, files in os.walk(os.path.abspath('html/')):
      for html_file in files:
         html_files.append("%s/%s" %(root, html_file))
   if not any(hash in s for s in html_files):
      
      html_file = 'html/%s.html' %hash
      string_list = []
      string_list.append("<html>\n")
      string_list.append("<head>\n")
      string_list.append("<title> %s </title>\n" %file)
      string_list.append("</html>\n")
      string_list.append("<body>\n")
      string_list.append("<h1>%s<br>SHA1: %s</h1>\n" % (file,hash))
      string_list.append("<h2>The file triggered on the following rules:<h2>\n") 
      string_list.append("<h3font color='%s'>%s</h3>\n" % (bg_color, rule))
      try:
         string_list.append("<h3>%s</h3>\n" %data.meta['description'])
      except:
         string_list.append("<h3>No description available</h3>")
      string_list.append("<h3>%s</h3>\n" %date)
      string_list.append("=====================================================================================\n")
      string_list.append("</body>\n")
      string_list.append("</html>\n")
      write_file=open(html_file, 'w')
      for i in string_list:
         write_file.write(i)
      write_file.close()
      index_file=open('html/index.html', 'r')
      contents = index_file.readlines()
      index_file.close()
      write_index = contents.index('<ul>\n')
      string = "<li><a href='%s.html'>%s</a> %s</li><br>\n" %(hash, file, date)
      contents.insert(write_index +1, string)
      a = ''.join(contents)
      index_file = open('html/index.html', 'w')
      index_file.write(a)
      index_file.close()

 
   else:
      index = 0
      if severity == 0:
         return
      html_file = 'html/%s.html' %hash
      write_file = open(html_file, 'r')
      contents = write_file.readlines()
      write_file.close() 
      write_index = contents.index('</body>\n')
      string = "<h3font color='%s'>%s</h3>\n" % (bg_color, rule)
      try:
         string += "<h3>%s</h3>\n" %data.meta['description']
      except:
         string += "<h3>No description available</h3>\n"
      string += "<h3>%s</h3>\n" %date 
      string += "=====================================================================================\n"
      contents.insert(write_index -1, string)
      a = ''.join(contents)
      write_file = open(html_file, 'w')
      write_file.write(a)
      write_file.close()
      index_file = open('html/index.html', 'r')
      contents = index_file.readlines()
      string = "<li><a href='%s.html'>%s</a> %s</li><br>\n" %(hash, file, date)
      for i, s in enumerate(contents):
         if hash in s:
            index = i
      contents[index] = string
      a = ''.join(contents)
      write_file = open('html/index.html', 'w')
      write_file.write(a)
      write_file.close()                      

def mycallback(data):
  if data['matches']:
     print data
  return yara.CALLBACK_CONTINUE, data

def start(path, run_count):
   file_path=path
   rule_path="rules/"
   rule_files = []
   file_list = []
   rule_count = 0
   for root, dirs, files in os.walk(os.path.abspath(rule_path)):
      for file in files:
         rule_files.append("%s/%s" %(root, file))

   for i in rule_files:
      rule_count +=1
   if not rule_files:
      print "there were no rule files loaded"
      sys.exit()
   if daemon_mode and run_count == 0:
      print ("Loaded %s rules files to run against") % rule_count
   elif not daemon_mode:
      print "no"
      print ("Loaded %s rules files to run against") % rule_count      

   scan_file_count = 0
   for path, dirs, files in os.walk(file_path):
      for bad_file in files:
         if not os.path.isfile(os.path.join(path, bad_file)):
            continue
         else:
            file_list.append(os.path.join(path, bad_file))
            scan_file_count +=1
   if not file_list:
      if not daemon_mode:
         print ("there were no files to scan")
         sys.exit()
      else:
         return(0,0)
   
   print ("Loaded %s files to scan") %scan_file_count

   match_count = 0
   results = []

   for file_name in file_list:
      filehash = getfilehash(file_name.strip())
      matches = []
      string = ''
      for j in rule_files:
         split_file_name = j.split('/')[-1]
         try:
            rules = yara.compile(j, externals={'filename': '', 'filepath': '', 'extension': '', 'filetype': '', 'service': '', 'sync':''})
         except Exception as e:
            date = datetime.now().strftime("%y-%m-%d-%H-%M")
            log_file = open(errorlog, 'w')
            string = "time: %s; broke on the compile rule_file: %s;error: %s\n" %(date, j, e)
            log_file.write(string)
            log_file.close()
            errors = True
             
         if verbose:
            try:
               matches.update(rules.match(file_name.strip()), callback=mycallback)
            except Exception as e:
               date = datetime.now().strftime("%y-%m-%d-%H-%M")
               log_file = open(errorlog, 'w')
               string = "time: %s; broke on the match; rule_file: %s; file_name: %s; error: %s\n" %(date, j, file_name, e)
               log_file.write(string)
               log_file.close()
               errors = True
         else:
            try:
               match = rules.match(file_name.strip())
               if match:
                  matches.append(match)
            except Exception as e:
               date = datetime.now().strftime("%y-%m-%d-%H-%M")
               log_file = open(errorlog, 'w')
               string = "time: %s; broke on the match; rule_file: %s; file_name: %s; error: %s\n" %(date, j, file_name, e)
               log_file.write(string)
               log_file.close()
               errors = True

      if not matches:
         print "no matches here"
         makehtml(0, file_name.strip(), filehash, 0)
      else:
         for j in matches:
            for i in j:
               status = ''
               description = ''
               rule_level = 0
               try:
                  description = i.meta['description']
               except:
                  description = "No description available"
               if split_file_name.lower().startswith("apt") or split_file_name.lower().startswith("toolkit") or split_file_name.lower().startswith("rat"):
                  rule_level = 1
                  status = "VERY BAD"
               elif split_file_name.lower().startswith('malw') or split_file_name.lower().startswith("maldoc"):
                  rule_level = 2
                  status = "BAD"
               elif split_file_name.lower().startswith("crime") or split_file_name.lower().startswith("cve") or split_file_name.lower().startswith('gen'):
                  rule_level = 3
                  status = "Not as bad"
               elif split_file_name.lower().startswith("crypto") or split_file_name.lower().startswith("ransom"):
                  rule_level = 4
                  status = "crimeware"
               elif split_file_name.lower().startswith('exploit') or split_file_name.lower().startswith('ek'):
                  rule_level = 5
                  status = "exploits"
               elif split_file_name.lower().startswith('base64') or split_file_name.lower().startswith('domain'):
                  rule_level = 6
                  status = "internal indicator"
               else:
                  rule_level = 10
                  status = "unclassified rule"

               string = "Alert status: %s\n" %status
               string += "File name: %s\n" % file_name.strip()
               string += "rulefile: %s\n" %j
               string += "Rules: %s\n" %i.rule
               string += "Description: %s" %description
               string += "hash is: %s\n\n" % filehash
               match_count +=1
               return_dict = {'return_string':string, 'indicator_level':rule_level}
               results.append(return_dict)
               makehtml(i, file_name.strip(), filehash, status)

   return(results, match_count)


def write_data(results, count):
   if errors:
      print "finished but there where errors, be sure to check the error log under logs/errors"
   run_time = datetime.now().strftime("%y-%m-%d-%H-%M")
   if len(results) > 0:
      open_file = 'reports/yara_check_output_%s.txt' %run_time
      write_file = open(open_file, 'w')
      for level in range (1,11):
         for i in results:
            if i['indicator_level'] == level:
               write_file.write(i['return_string'])
      write_file.close()
      if not auto_open:
         print ("there where %s matches returned, do you want to view them in the console?") %count
         input = raw_input("Yes?/No?\n")
         if input.lower() == "yes":
            print ("The results that were found are listed below\n\n")
            for level in range (1,11):
               for i in results:
                  if i['indicator_level'] == level:
                     print (i['return_string'])
                     raw_input("Press enter to continue")
   else:
      print ("No fields matched")

def daemon(malware_path):
   run_count = 0
   while True:
      results, count = start(malware, 0)
      if not count == 0:
         write_data(results, count)  
         for root, dirs, files in os.walk(os.path.abspath('malware/')):
            for malware_file in files:
               move('%s/%s' %(root, malware_file), "backup/malware/%s" %malware_file)
      run_count +=1         
      sleep(60)

if __name__ == "__main__":
   start_time = time()
   # construct the argument parse and parse the arguments
   ap = argparse.ArgumentParser()
   ap.add_argument("-d", "--daemon", help="puts the script in daemon mode, when the script has parsed the malware it will place it in /backup/malware.  The script will continuely check the malware path, so you can add new malware at any time and it will parse it, will not print to console, only to HTML and REPORTS",
        action='store_true') 
   ap.add_argument("-p", "--path", help="path to malware defualt is malware/")
   ap.add_argument("-v", "--verbose", required=False,
        action='store_true', help="Triggers verbose output")
   ap.add_argument("-o", "--auto", action='store_true',
        help="Automatically opens the output file \nNote: Not implemented")
   ap.add_argument("-r", "--reset", action='store_true', help="This will reset all the files")

   args = vars(ap.parse_args())
   #End of arguments

   if args['path']:
      malware = args['path']
   else:
      malware = 'malware/'
   if args['verbose']:
      print "setting logging to verbose, alot of shit is coming to the screen"
      raw_input("press enter to continue")
      verbose = True
   if args['auto']:
      auto_open = True
   if args['reset']:
      reset()
   if args['daemon']:
      daemon_mode = True
      auto_open = True
      daemon(malware)
   else:
      print "loading possibly malicious files located here: \n%s" %malware
      results, count = start(malware, 0)
      write_data(results, count)  
      print ("Run is done")
      print ("Total runtime: %f seconds") % (time() - start_time)           