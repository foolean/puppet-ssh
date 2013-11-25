# sshversion.rb

# Get the version string from 'ssh -V'
version_string = Facter::Util::Resolution.exec('/usr/bin/ssh -V 2>&1')
array1 = version_string.split(/,/)
array2 = array1[1].split(/ /)

Facter.add("sshversionstring") do
    setcode do
        version_string
    end
end

Facter.add("sshtype") do
    setcode do
        (array1[0].split(/_/))[0]
    end
end

Facter.add("sshversion") do
    setcode do
        (((array1[0].split(/_/))[1]).split(/ /))[0]
    end
end

Facter.add("sshsslversion") do
    setcode do
        array2[2]
    end
end
