def storage_disk_list(name, human_readable=False):
    from yunohost.disks import info

    return info(name, human_readable=human_readable)

def storage_disk_info(with_info=False, human_readable=False):
    from yunohost.disks import list

    return list(with_info=with_info, human_readable=human_readable)
