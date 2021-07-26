import os
import shutil
import subprocess

from setuptools import setup
from setuptools.command.build_py import build_py


class build_hallucinate(build_py):
    def run(self):
        super(build_hallucinate, self).run()
        try:
            subprocess.run(['mvn', 'clean', 'package'], cwd='java', check=True)
            if not self.dry_run:
                target = os.path.join(self.build_lib, 'hallucinate/hallucinate-java-all.jar')
                shutil.copy('java/target/hallucinate-java-1.0-SNAPSHOT-all.jar', target)
        except Exception as e:
            print("Maven build failed, Java support will not be active: " + str(e))


setup(
    name='hallucinate',
    version='1.0.0',
    packages=['hallucinate', 'hallucinate.handlers'],
    zip_safe=False,
    url='',
    license='',
    author='mbechler',
    author_email='',
    description='Binary Instrumentation to intercepted clear-text application traffic.',
    install_requires=['frida', 'psutil'],
    entry_points={
        "console_scripts": [
            "hallucinate = hallucinate.__main__:main"
        ]
    },
    console=['scripts/hallucinate.py'],
    include_package_data=True,
    cmdclass={'build_py': build_hallucinate}
)
