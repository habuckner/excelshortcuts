import pandas as pd
import numpy as np
import os
import tkinter as tk
from tkinter import filedialog

## --- For showing the file open box
root = tk.Tk()
root.withdraw()
root.call('wm', 'attributes', '.', '-topmost', True)
input_file = filedialog.askopenfilename(title="Select file", filetypes=(("Excel files", "*.xlsx"),("Excel files", ".xls")))
print(f'INFO: Seleceted Input File : {input_file}')

## Output file: to be dumped at the same location of input file.
path,inputfname = os.path.split(input_file)
output_file_name = 'output.txt'
output_file= path + '/' + output_file_name

xls = pd.ExcelFile(input_file)
sheets=xls.sheet_names
sheet = sheets[0]
df = xls.parse(sheet)
[df[col].astype(str) for col in df.columns]

# Row deletion when keywords match
row_deletion_keywords = ['SDC', 'SHape' , 'SHP', 'SIlverline', 'Voltera','ThreatStack']
df_new = df[~df.apply(lambda row: row.astype(str).str.contains('|'.join(row_deletion_keywords),case=False).any(), axis=1)].reset_index()

############### Column Names
# From Input Excel 
org_unit_path = 'Organization Unit Path'
cloud_acc = 'Cloud Account'
entity_name = 'Entity Name'
rule_name = 'Rule Name'
created_time ='Created Time'
description = 'Description'
redemption ='Remediation'
finding_key='Finding Key'
severity='Severity'
assignee='Assignee'
# Assumed from output file text 
environment='Environment'
owner='Owner'
associates='Associates'

# Output file creation for writing
fout=open(output_file,'w')

agg_functions = {
'Cloud Account':  lambda x: ', '.join(x) ,
'Entity Name':  lambda x: ', '.join(x) , 
'Rule Name': lambda x: ', '.join(x) ,
'Created Time' :  lambda x: ', '.join(x),
'Description':  lambda x: ', '.join(x),
'Remediation' :  lambda x: ', '.join(x),
'Finding Key' :  lambda x: ', '.join(x),
'Severity' :  lambda x: ', '.join(x),
'Assignee' :  lambda x: ', '.join(x),
'Owner' :  lambda x: ', '.join(x), 
'Associates' :  lambda x: ', '.join(x)
}

#create new DataFrame by combining rows with same id values
df_mod = df_new.groupby(org_unit_path).aggregate(agg_functions)
df_mod = df_mod.reset_index()


for index, row in df_mod.iterrows():
    val_org_unit_path=df_mod.iloc[index][org_unit_path]
    val_cloud_acc=df_mod.iloc[index][cloud_acc]
    val_entity_name=df_mod.iloc[index][entity_name]
    val_rule_name=df_mod.iloc[index][rule_name]
    val_created_time=df_mod.iloc[index][created_time]
    val_description=df_mod.iloc[index][description]
    val_redemption=df_mod.iloc[index][redemption]
    val_finding_key=df_mod.iloc[index][finding_key]
    val_severity=df_mod.iloc[index][severity]
    val_assignee=df_mod.iloc[index][assignee]
    val_owner=df_mod.iloc[index][owner]
    val_associates=df_mod.iloc[index][associates]
    val_unit_path=df_mod.iloc[index][org_unit_path].split('/')[-1]

    line = f"\n\
Owner: {val_owner}\n\
Associates: {val_associates}\n\
Assignee: {val_assignee}\n\
Embedded Contacts: {val_unit_path} \n\
Service or applicationVulnerability Management \n\
Module    CloudGuard \n\
Data Classification    {val_severity} \n\
Short description {val_org_unit_path} {val_cloud_acc} \n\
Description Hello, this is a ticket from CloudGuard. \n\
\n\
CLOUDGUARD NOTIFICATION: SYSTEM VULNERABILITY \n\
\n\
Severity: {val_severity} \n\
Organizational Unit Path:{val_org_unit_path} \n\
Cloud Account Name:{val_cloud_acc} \n\
\n\
Create Time | Entity | Finding Key: \n\
{val_created_time} | {val_entity_name} | {val_finding_key}\n\
\n\
Description:\n\
Excessive permissions were granted to IamRole: {val_entity_name}.  Setting excessive permissions increases your attack surface.  Please take suggested remediation steps to ensure only necessary privileges re assigned. \n\
\n\
Rule: \n\
Overprivileged iamRole \n\
\n\
Remediation: \n\
After reviewing the suggested changes, replace your current policy with suggested policy. \
\n\
Next Steps: \n\
Log into your Check Point CloudGuard account to review your EVENTS > Posture Findings and Threat & Security Events.  You may lookup the events shown in this ticket by entering the 'Finding Key' into the CloudGuard filter. \n\
\n\
NOTE:  \n\
At ___ it is important to maintain a strong cloud security posture.  Especially when remediating Critical findings, timely action and maintaining your security SLAs is required.  Please advise if you may need further guidance on remediation. \n\
\n\
-------------------"     
    fout.write(line + '\n')
    #print(line)

fout.close()
print(f'INFO: Input Excel File processed Successfully.\nINFO: Output File Generated : {output_file}')