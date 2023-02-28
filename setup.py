from setuptools import setup, find_packages

setup(name='compiler_idioms',
      version='0.1',
      description='Matches compiler idioms in a given binary file',
      url='https://github.com/fkie-cad/dewolf-idioms',
      author='Fraunhofer FKIE',
      author_email='dewolf@fkie.fraunhofer.de',
      license='MIT',
      packages=find_packages(),
      package_data={'': ['patterns/*']},
      zip_safe=False)
