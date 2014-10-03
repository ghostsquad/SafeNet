namespace SafeNet.Acl {
    using System;

    [Flags]
    public enum AccessRuleProtectionOptions {
        None = 0,
        Protected = 1,
        PreserverInheritance = 2
    }
}