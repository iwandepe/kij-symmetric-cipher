from fileinput import filename
import time
import pandas as pd
import os


class Analizer:
    def __init__(
        self, 
        _target,
        _method=None,
        _mode=None
    ):
        self.method = _method
        self.mode = _mode
        self.name = self.translate_mode()
        self.startTime = 0
        self.endTime = 0
        self.totalTime = 0
        self.path = '../results/record.csv'
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
            'METHOD': [ self.method ],
            'MODE': [self.name],
            'FILENAME': [ fileName ],
            'SIZE_BYTE': [ fileSize ],
            'ELAPSED_SEC': [ self.totalTime ]
        }

        print('\n')
        print( f"[*] Encryption completed :" )
        print( f"[*] Result: {data}" )

        self.addingRecordToCsv(data)

    def addingRecordToCsv(self, _toBeAppended):
        df = pd.DataFrame(_toBeAppended, columns=['METHOD','MODE', 'FILENAME','SIZE_BYTE','ELAPSED_SEC'])
        isExist = os.path.isfile(self.path)

        if (isExist):
            dfOld = pd.read_csv(self.path)
            dfNew = pd.concat([dfOld, pd.DataFrame.from_records(df)])
            dfNew.to_csv(self.path, columns=['METHOD','MODE', 'FILENAME','SIZE_BYTE','ELAPSED_SEC'], index=True)

            print( '[*] Record successfully added.' )
            return
        
        df.to_csv(self.path)
        print( 'data successfully added' )
    
    def dfDescribe(self):
        pd.read_csv(self.path).describe()

    def getElapsedSeconds(self):
        return self.totalTime * 1000

    def translate_mode(self):
        if(self.mode==1): 
            return 'MODE_ECB'
        if(self.mode==2): 
            return 'MODE_CBC'
        if(self.mode==3): 
            return 'MODE_CFB'
        if(self.mode==5): 
            return 'MODE_OFB'
        if(self.mode==6): 
            return 'MODE_CTR'
        if(self.mode==7): 
            return 'MODE_OPENPGP'
        if(self.mode==8): 
            return 'MODE_CCM'
        if(self.mode==9): 
            return 'MODE_EAX'
        if(self.mode==10): 
            return 'MODE_SIV'
        if(self.mode==11): 
            return 'MODE_GCM'
        if(self.mode==12): 
            return 'MODE_OCB'