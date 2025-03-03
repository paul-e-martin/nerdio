# Contributing
1. Create a branch for your application.
2. Create a folder for your required script.
3. Create a file for your script with the extension **.ps1**. The script name, will be the application name minus the file extension.
4. Ensure the script is in the following format:
````powershell
<#
    .SYNOPSIS

    .DESCRIPTION
        #description:
        #execution mode:
        #tags:

    .NOTES

#>

begin {

}

process {

}

end {

}
````

- Synopsis: Brief overview of the script.
- Description:
    - #description: This is the description that is visible in the Nerdio MSP application.
    - #execution mode: This is how the script is handed. Possible values are: **Individual**, **IndividualWithRestart** or **Combined**.
    - #tags: Tags for grouping and organising scripts within Nerdio MSP.
- Notes: Any notes for usage.
5. Merge the branch and squash the commits.
