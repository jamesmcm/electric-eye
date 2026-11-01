//! Shared capture and classification policy for built-in credential locations.

pub const SYSTEM: &[&str] = &[
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/sudoers.d",
];

pub const HOME: &[(&str, &str)] = &[
    (".ssh", "SSH"),
    (".gnupg", "GnuPG"),
    (".aws", "AWS credentials"),
    (".azure", "Azure credentials"),
    (".kube", "Kubernetes credentials"),
    (".config/gcloud", "GCloud credentials"),
    (".config/gh", "GitHub CLI credentials"),
    (".config/keepassxc", "Password manager"),
    (".local/share/keyrings", "Password manager"),
    (".password-store", "Password manager"),
    (".git-credentials", "Git credentials"),
    (".netrc", "Git credentials"),
];

pub const BROWSERS: &[&str] = &[
    ".mozilla/firefox",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware/Brave-Browser",
];

pub const BROWSER_FILES: &[&str] = &[
    "logins.json",
    "key4.db",
    "key3.db",
    "cookies.sqlite",
    "Login Data",
    "Cookies",
];
