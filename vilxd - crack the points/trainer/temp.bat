$extensions = @(
    "aaron-bond.better-comments",
    "akamud.vscode-theme-onedark",
    "dbaeumer.vscode-eslint",
    "dotjoshjohnson.xml",
    "eamodio.gitlens",
    "esbenp.prettier-vscode",
    "evan-buss.font-switcher",
    "formulahendry.auto-complete-tag",
    "formulahendry.auto-rename-tag",
    "jkiviluoto.tws",
    "n3rds-inc.image",
    "pkief.material-icon-theme",
    "ritwickdey.LiveServer",
    "rs1rkfndmrky.rsl-vsc-focused-folder",
    "simonsiefke.svg-preview",
    "streetsidesoftware.code-spell-checker",
    "tababasri.snippets",
    "vmsynkov.colonize",
    "wayou.vscode-todo-highlight",
    "wix.vscode-import-cost",
    "yamato-ltd.vscode-aem-sync"
)
ForEach ($ext in $extensions) {
    code --install-extension $ext --force
}