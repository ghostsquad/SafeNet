namespace SafeNet.Test.Common {
    using System.Collections;
    using System.Reflection;
    using System.Security;

    using FluentAssertions;

    using SafeNet.Core;

    public static class AssertEx {
        public static void PropertyValuesShouldBeEqual(this object actual, object expected) {
            PropertyInfo[] properties = expected.GetType().GetProperties();
            foreach (PropertyInfo property in properties) {
                object expectedValue = property.GetValue(expected, null);
                object actualValue = property.GetValue(actual, null);

                var actualList = actualValue as IList;
                if (actualList != null) {
                    actualList.ShouldBeEquivalentTo(expectedValue);
                } else if (!(actualValue is SecureString)) {
                    var message = string.Format(
                        "Property {0}.{1} does not match. Expected: {2} but was: {3}",
                        property.DeclaringType.Name,
                        property.Name,
                        expectedValue,
                        actualValue);
                    actualValue.Should().Be(expectedValue, message);
                }                  
            }
        }

        public static void CompareSecrets(ISecret actual, ISecret expected, bool compareId = true) {
            actual.Should().NotBeNull();
            expected.Should().NotBeNull();

            if (compareId) {
                actual.Identifier.Should().Be(expected.Identifier);
            }

            actual.Target.Should().Be(expected.Target);
            actual.Username.Should().Be(expected.Username);
            actual.Password.Should().Be(expected.Password);
            actual.Meta.ShouldBeEquivalentTo(expected.Meta);
        }
    }
}
