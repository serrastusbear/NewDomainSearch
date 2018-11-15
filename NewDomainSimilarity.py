# Script to import newly registered domains, then perform specified similarity tests against a supplied
# list of terms to identify related items, such as typo-squats and domain similars.
# Requires a wordlist as mandatory input, with one item per line, to use as basis for matching.

# Released under GNU GPLv3

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
__author__ = 'Joe Slowik, Dragos Inc.'

import math, requests, os, zipfile, io, datetime, difflib, editdistance, argparse

def argumentParser():
    parser = argparse.ArgumentParser()
    parser.add_argument('wordlist', action='store', help='Word List file to use for similarity matches')
    parser.add_argument('outputDirectory', action='store', help='Location for output, default is CWD')
    parser.add_argument('-t', '--type', choices=['s','e','j'], default='s', help='''Pick similarity calculation type:s
                                                                                 for difflib similarity, e for edit
                                                                                 distance, J for Jaccard''')
    return parser.parse_args()

class Domain:
    def __init__(self,score,domain):
        self.score = score
        self.domain = domain
    def __repr__(self):
        return repr((self.score,self.domain))

def jaccardTest(newDomain,listItem):
    intersection_cardinality = len(set.intersection(*[set(newDomain),set(listItem)]))
    union_cardinality = len(set.union(*[set(newDomain),set(listItem)]))
    return intersection_cardinality/float(union_cardinality)
    #Using example from http://dataconomy.com/2015/04/implementing-the-five-most-popular-similarity-measures-in-python/

def calculatePreviousDay():
    today = datetime.datetime.utcnow().date()
    yesterday = today - datetime.timedelta(days=1)
    yesterdayDate = yesterday.strftime("%Y-%m-%d")
    return yesterdayDate

def retrieveDomainList():
    #Retrieve list of new domains
    date = calculatePreviousDay()
    domainlist = []
    headers = { 'User-Agent': 'Threat Intelligence Research'}
    dateValue = date + '.zip'
    dateB64 = base64.b64encode(dateValue.encode('utf-8')).decode('utf-8')
    #format: https://whoisds.com//whois-database/newly-registered-domains/YYYY-MM-DD.zip/nrd
    url = 'https://whoisds.com/whois-database/newly-registered-domains/' + dateB64 + '/nrd'
    #print(url)
    try:
        response = requests.get(url)
        #print(str(response.content))
        try:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zipresponse:
               #print('opened zip')
               for zipinfo in zipresponse.infolist():
                   #print('get list of subfiles')
                   with zipresponse.open(zipinfo) as thefile:
                       #print('open subfile')
                       for line in thefile:
                           #print(str(line))
                           item = line.decode('ascii')
                           domainlist.append(str(item).rstrip('\r\n'))
        except:
            print('Error in processing Zip')
    except:
        print("Error in retrieving response.")
    return domainlist

def scoringFunction(args, dictionary, domains):
    scoredList = []
    for domain in domains:
        item = domain.split('.')[0]
        #print(item)
        tempVal = 0.0
        for record in dictionary:
            #print(record)
            if args != '':
                if args == 's':
                    seqmatch = difflib.SequenceMatcher(None,item,record)
                    score = seqmatch.ratio()
                    #print(str(score))
                elif args == 'e':
                    score = 100 - editdistance.eval(item,record)
                    #print(str(score))
                elif args == 'j':
                    score = jaccardTest(item,record)
                    #print(str(score))
            #print("Score: " + str(score))
            if score > tempVal:
                tempVal = score
        if tempVal < 0.5:
            pass
        else:
            domainRecord = Domain(tempVal,domain)
            #print(str(domainRecord))
            scoredList.append(domainRecord)
    return scoredList


def openFileReturnAsList(fileLocation):
    dictionaryList = []
    try:
        with open(fileLocation) as file:
            for line in file:
                #print(line)
                dictionaryList.append(line.strip())
    except:
        print("Error opening file location: " + fileLocation)
    return dictionaryList

if __name__ == '__main__':
    parser = argumentParser()
    #print('Selected function: ' + parser.type)
    dictionaryList = openFileReturnAsList(parser.wordlist)
    #print("Dictionary list loaded")
    domainList = retrieveDomainList()
    #print("Domain list retrieved")
    scorelist = scoringFunction(parser.type, dictionaryList, domainList)
    #print("Scoring function complete")
    if parser.type == 's':
        type = "similarity"
    elif parser.type == 'e':
        type = "editdistance"
    elif parser.type == "j":
        type = "jaccard"
    sortScore = sorted(scorelist, key=lambda Domain: Domain.score, reverse=True)
    fileName = parser.outputDirectory + 'newDomains_' + calculatePreviousDay() + '_' + type + '.txt'
    with open(fileName,'w') as file:
        for item in sortScore:
            file.write(str(item)+'\n')
