import matplotlib.pyplot as plt
import numpy as np
#from matoplotlib.colors import LogNorm
from math import sqrt

dx,dy = 1.0,1.0
n = 53*71

y,x = np.mgrid[slice(0,n+dy,dy),
               slice(0,n+dx,dx)]
#z = np.abs(x*y-n)
z = np.abs(x**2-y**2)%n
z = z[:-1,:-1]
for i in range(n):
    for j in range(n):
        if z[i][j]!=0: z[i][j]=1
        if i==j: z[i][j]=1
        if i+j==n: z[i][j]=1

z_min, z_max = np.min(z),np.max(z)

fig,ax = plt.subplots(1,1)
c = ax.pcolormesh(x,y,z,cmap='Reds',vmin=z_min,vmax=z_max)
#ax.plot(53,71,marker="x",markersize=3,color="b")
#ax.plot(71,53,marker="x",markersize=3,color="b")
ax.set_title("pcolormesh")
ax.axis([x.min(),x.max(),y.min(),y.max()])
fig.colorbar(c,ax=ax)

plt.show()
