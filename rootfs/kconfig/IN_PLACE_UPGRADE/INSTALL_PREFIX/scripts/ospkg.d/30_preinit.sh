
# Copyright (c) 2015, Plume Design Inc. All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the Plume Design Inc. nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


ospkg_preinit_mount_overlay()
{
    # move all mounts to /rom
    ospkg_move_and_pivot_root /rom /rom/tmp/old_overlay
    # remount /overlay with additional layer
    local LAYERS=$(ospkg_mount_active_layer "/overlay/upper")
    LAYERS=${LAYERS:-/}
    mount -t overlay overlayfs:/overlay -o rw,noatime,lowerdir=$LAYERS,upperdir=/overlay/upper,workdir=/overlay/work /overlay
    # move all mounts to new /overlay
    ospkg_move_and_pivot_root /overlay /overlay/rom
    mount --move /rom/overlay/ /overlay
    # to unmount old_overlay we need to re-exec to release the fs
    # since this process is running from the old_overlay
    exec $(readlink -f "$0") call ospkg_preinit_mount_cleanup
}

ospkg_preinit_mount_cleanup()
{
    # unmount /tmp/old_overlay
    umount /tmp/old_overlay
    rmdir /tmp/old_overlay
}

