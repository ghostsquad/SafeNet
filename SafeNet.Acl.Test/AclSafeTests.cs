using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Text;
using System.Threading.Tasks;

using Moq;

using Ploeh.AutoFixture;

using SafeNet.Core;
using SafeNet.Test.Common;

using Xunit;

namespace SafeNet.Acl.Test {
    public class AclSafeTests {

        private readonly Testable<AclSafe> testable;

        private readonly Mock<EnvironmentWrapper> environmentMock;

        public AclSafeTests() {
            this.testable = new Testable<AclSafe>();
            this.environmentMock = this.testable.InjectMock<EnvironmentWrapper>();
        }

        [Fact]
        public void WhenConstructedCreatesDirectory() {
            var expectedFileName = Guid.NewGuid().ToString();

            var fileSystemInfoMock = this.testable.InjectMock<FileSystemInfo>();
            fileSystemInfoMock.SetupGet(x => x.FullName).Returns(expectedFileName);

            var actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.CreateDirectory(expectedFileName), Times.Once());
        }

        [Fact]
        public void WhenProtectedAssignsFileSystemAccessRulesToSafe() {
            var securityMock = this.testable.InjectMock<FileSystemSecurity>();
            this.testable.ClassUnderTest.Protect(securityMock.Object);
            this.environmentMock.Verify(
                x => x.SetAccessControl(this.testable.ClassUnderTest.SafeObject, securityMock.Object),
                Times.Once());
        }

        [Fact]
        public void WhenProtectedWithRulesAssignsRulesToSafe() {
            var rules = this.testable.Fixture.CreateMany<FileSystemAccessRule>().ToList();
            this.testable.ClassUnderTest.Protect(rules);
        }
    }
}
