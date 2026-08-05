subdir-ccflags-y += -Werror
subdir-ccflags-y += -Wno-unused-variable
subdir-ccflags-y += $(call cc-disable-warning, unused-but-set-variable)

obj-$(CONFIG_OPPO_MOTOR) += camera_motor_ic/
obj-$(CONFIG_OPPO_MOTOR) += digital_hall_ic/

obj-$(CONFIG_OPPO_MOTOR) += oppo_motor.o
obj-$(CONFIG_OPPO_MOTOR) += oppo_motor_notifier.o