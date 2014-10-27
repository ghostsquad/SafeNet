namespace SafeNet.Test.Common {
    using System.Collections;
    using System.Reflection;
    using System.Security;

    using FluentAssertions;

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
    }
}
