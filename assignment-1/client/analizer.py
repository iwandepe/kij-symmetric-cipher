from fileinput import filename
import time
import pandas as pd
import os

class Analizer:
    def __init__(
        self, 
        _name, 
        _path, # record data
        _target # targeted file to encrypt
    ):
        self.name = _name
        self.startTime = 0
        self.endTime = 0
        self.totalTime = 0
        self.path = _path
        self.target = _target
    
    def startTimer(self):
        self.startTime = time.time()

    def endTimer(self):
        self.endTime = time.time()
        self.totalTime = self.endTime - self.startTime
    
    def addToRecord(self):
        fileSize = os.path.getsize( self.target )
        fileName = os.path.basename( self.target )
        data = {
            'method': [ self.name ],
            'fileSize': [ fileSize ],
            'fileName': [ fileName ],
            'totalTime': [ self.totalTime ]
        }

        self.addingRecordToCsv(data)

    def addingRecordToCsv(self, _toBeAppended):
        df = pd.DataFrame(_toBeAppended, columns=['method', 'totalTime','fileSize','fileName'])
        isExist = os.path.isfile(self.path)

        if (isExist):
            dfOld = pd.read_csv(self.path)
            print(dfOld.iloc[0])
            dfOld = dfOld.append( df )
            dfOld.to_csv(self.path, columns=['method', 'totalTime','fileSize','fileName'], index=True)
            print( 'data successfully added' )
            return
        
        df.to_csv(self.path)
        print( 'data successfully added' )
    
    def dfDescribe(self):
        pd.read_csv(self.path).describe()