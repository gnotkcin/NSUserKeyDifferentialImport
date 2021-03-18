# NSUserKeyDifferentialImport
Differentially import UserKeys from NetSkope into JAMF & optionally generate nsbranding.json configuration files.

This is required when deploying NetSkope to Macs that are using local accounts – NetSkope is unable to retrieve UserKeys to generate nsbranding.json configuration files when the console user is not an Active Directory account.

## Summary
The Server-Side `NSUserKeyDifferentialImport` gets a list of all computers from JAMF, reduces that list to computers with missing UserKeys, gets a UserKey from NetSkope for each of those computers, and then updates each of those computers in JAMF with the corresponding UserKey returned by NetSkope.

The Client-Side `NSUserKeyDifferentialImportHelper` gets a given computer's UserKey from JAMF and writes that UserKey into nsbranding.json on each computer.

## Getting Started

Just download and run `NSUserKeyDifferentialImport.py`

A first run setup assistant will walk you through configuration and usage.

If you'd like to come prepared, be sure you have:

* FQDN of the NetSkope instance (eg: nicktong.goskope.com)
* NetSkope token with permission to read the NetSkope UserConfig endpoint
* FQDN of the JAMF instance (eg: nicktong.jamfcloud.com)
* JAMF Username & Password of an account with read + update permissions for computers and users
* JAMF Extension Attribute with an input type of "text field" for storing NetSkope UserKeys

## Usage
To configure the tool, run:

```shell
NSUserKeyDifferentialImport.py --configure
```

When testing the tool, enable verbose mode to log to stdout and set a finite limit to avoid processing all computer records:

```shell
NSUserKeyDifferentialImport.py --limit 100 -v
```

When running the tool as a scheduled job, do not pass any options - this ensures that all computer records are processed without printing any sensitive information to stdout:

```shell
NSUserKeyDifferentialImport.py
```

To generate a nsbranding.json configuration file on each Mac, deploy `NSUserKeyDifferentialImportHelper.sh` as a JAMF policy script.

There is absolutely no need to continue reading unless you have an interest in how this tool works.

## Logical Overview
![Logical Diagram](https://github.com/gnotkcin/NSUserKeyDifferentialImport/blob/master/READMEAssets/NSUserKeyDifferentialImport.png)

## Logical Description
NSUserKeyDifferentialImport fetches a list of all computer IDs and names (jamfIdentifierPair) from JAMF and, for each jamfIdentifierPair, instantiates the Computer() class, resulting in a single computer object corresponding to each jamfIdentifierPair.

Computer()'s initialization method fetches and assigns values to a number of properties that may be of interest to the you, including:

* jid (jamf computer_id)
* udid (jamf unique device identifier)
* name (jamf computer_name)
* email (jamf email_address)
* userkey (value from jamf extension attribute that stores the NetSkope user key)

Each computer object that has an empty userkey value is then stored in the [computers] list, while computer objects with a non-empty userkey value are discarded because those do not need to re-import a userkey value.

Once the [computers] list is populated with computer objects representing each JAMF computer record having an empty userkey, NetSkope is queried for a userkey using the computer object's e-mail property value. If NetSkope returns a userkey, the corresponding computer object is is mutated by assigning the returned value to the computer object's userkey property.

Once each computer object is updated with a userkey (or error(s) in the absence of a userkey), the list is iterated one last time to post the userkeys to JAMF.

## Portability & Dependencies
NSUserKeyDifferentialImport maintains platform portability between macOS, Windows and Linux.

Credential storage is platform specific: Tokens required to access NetSkope and JAMF APIs are managed on each of these platforms with a given platform's native keyring backend provider:

* Apple Keychain on macOS
* Microsoft Credential Locker on Windows

Support for these and other keyring providers is enabled by dependency on the Python Keyring Library.

Additional Dependencies Include:

* `plistlib` for preference list serialization and deserialization

There is no need to manually install these - `NSUserKeyDifferentialImport` resolves dependencies on launch.

## Colophon
NSUserKeyDifferentialImport is maintained by The Boston Consulting Group.

It was developed by Nick Tong with contributions from Shaon Jana and Yogesh Dhinwa.

![Open Source Initiative Approved License](https://github.com/gnotkcin/NSUserKeyDifferentialImport/blob/master/READMEAssets/OSILogo.png)

The MIT License

Copyright © 2020 The Boston Consulting Group, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
