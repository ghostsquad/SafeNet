namespace SafeNet.Core {
    using System;

    [Flags]
    public enum SafeSearchOptions {
        Wildcard = 0,
        Regex = 1
    }
}