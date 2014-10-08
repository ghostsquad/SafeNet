namespace SafeNet.Acl.Test {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.AccessControl;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;

    using FluentAssertions;

    using Moq;

    using Ploeh.AutoFixture;
    using Ploeh.AutoFixture.Kernel;

    using SafeNet.Core;
    using SafeNet.Test.Common;

    using Xunit;

    public class FileAclSafeTests : IDisposable {
        private readonly Testable<FileAclSafe> testable;

        private readonly Mock<EnvironmentWrapper> environmentMock;

        private readonly string expectedFileName;

        public FileAclSafeTests() {
            this.testable = new Testable<FileAclSafe>();
            this.environmentMock = this.testable.InjectMock<EnvironmentWrapper>();
            this.expectedFileName = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        }

        private FileInfo GetRealRandomFile() {
            File.WriteAllText(this.expectedFileName, string.Empty);
            return new FileInfo(this.expectedFileName);
        }

        [Fact]
        public void WhenConstructedCreatesFileIfNotExists() {
            this.testable.Fixture.Register(() => new FileInfo(this.expectedFileName));
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(false);
            var actual = this.testable.ClassUnderTest;
            this.environmentMock.Verify(x => x.WriteAllText(this.expectedFileName, It.IsAny<string>()), Times.Once());
        }

        [Fact]
        public void WhenConstructedAndFileExistsNoChange() {
            this.testable.Fixture.Register(() => new FileInfo(this.expectedFileName));
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(true);
            var actual = this.testable.ClassUnderTest;
            this.environmentMock.Verify(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()), Times.Never());
        }

        [Fact]
        public void WhenProtectedAssignsFileSystemAccessRulesToSafe() {
            var realFile = this.GetRealRandomFile();
            var security = realFile.GetAccessControl();
            this.RegisterCurrentUserInFixture();
            this.testable.Fixture.Register(() => realFile);

            this.testable.ClassUnderTest.Protect(security);
            this.environmentMock.Verify(
                x => x.SetAccessControl(this.testable.ClassUnderTest.SafeObject, security),
                Times.Once());
        }

        [Fact]
        public void WhenProtectedWithRulesAssignsRulesToSafe() {
            this.RegisterCurrentUserInFixture();
            this.testable.Fixture.Register(this.GetRealRandomFile);
            this.testable.Fixture.Register(() => InheritanceFlags.None);
            this.testable.Fixture.Register(() => PropagationFlags.None);
            var expectedRules = this.testable.Fixture.CreateMany<FileSystemAccessRule>().ToList();

            FileSystemSecurity actualSecurity = null;
            this.environmentMock.Setup(x => x.SetAccessControl(It.IsAny<FileInfo>(), It.IsAny<FileSystemSecurity>()))
                .Callback<FileSystemInfo, FileSystemSecurity>((x, y) => actualSecurity = y);

            this.testable.ClassUnderTest.Protect(expectedRules);

            var actualRules = actualSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

            actualRules.ShouldBeEquivalentTo(expectedRules);
        }

        public void Dispose() {
            if (File.Exists(this.expectedFileName)) {
                File.Delete(this.expectedFileName);
            }
        }

        private void RegisterCurrentUserInFixture() {
            this.testable.Fixture.Register<IdentityReference>(() => new NTAccount(WindowsIdentity.GetCurrent().Name));
        }
    }
}
