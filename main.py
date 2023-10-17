''' 
    Online_Tax_Services - HMRC VAT MTD Python wrapper
    Copyright (C) 2023 Ronin Customs Ltd.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

import sys
import online_tax_services

if __name__ == "__main__":

    ots = online_tax_services.OnlineTaxServices()

    if ots.run_mode == 'INSTALL':
        if ots.Install() != 0:
            print("install failed! exiting...")
            sys.exit(1)
        print("Install complete!")
        sys.exit(0)
    elif ots.run_mode == 'PASSWORD':
        if ots.ChangePassword() != 0:
            print("password change failed! exiting...")
            sys.exit(1)
        print("Password changed!")
        sys.exit(0)
    elif ots.run_mode == 'GENERATE':
        if ots.GenerateSecret() != 0:
            print("totp gen. failed! exiting...")
            sys.exit(1)
        print("TOTP secret generated!")
        sys.exit(0)

    if ots.run_mode != 'SHELL':
        print('invalid run mode! exiting...')
        sys.exit(1)

    ots.Run()
