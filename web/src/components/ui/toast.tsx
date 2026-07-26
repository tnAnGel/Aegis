import * as React from "react";
import * as ToastPrimitive from "@radix-ui/react-toast";
import { cva, type VariantProps } from "class-variance-authority";
import { X } from "lucide-react";
import { cn } from "@/lib/cn";

const ToastProvider = ToastPrimitive.Provider;

const ToastViewport = React.forwardRef<
    React.ElementRef<typeof ToastPrimitive.Viewport>,
    React.ComponentPropsWithoutRef<typeof ToastPrimitive.Viewport>
>(({ className, ...props }, ref) => (
    <ToastPrimitive.Viewport
        ref={ref}
        className={cn(
            "fixed bottom-0 right-0 z-[100] flex max-h-screen w-full flex-col-reverse gap-2 p-4 sm:max-w-[420px]",
            className,
        )}
        {...props}
    />
));
ToastViewport.displayName = ToastPrimitive.Viewport.displayName;

const toastVariants = cva(
    "group pointer-events-auto relative flex w-full items-center justify-between space-x-2 overflow-hidden rounded-md border p-4 pr-6 shadow-lg transition-all data-[swipe=cancel]:translate-x-0 data-[swipe=end]:translate-x-[var(--radix-toast-swipe-end-x)] data-[swipe=move]:translate-x-[var(--radix-toast-swipe-move-x)] data-[swipe=move]:transition-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[swipe=end]:animate-out data-[state=closed]:fade-out-80 data-[state=closed]:slide-out-to-right-full data-[state=open]:slide-in-from-bottom-full",
    {
        variants: {
            variant: {
                default: "border bg-card text-card-foreground",
                destructive:
                    "destructive group border-destructive bg-destructive text-destructive-foreground",
                success:
                    "border-success/40 bg-success/10 text-success",
            },
        },
        defaultVariants: { variant: "default" },
    },
);

const Toast = React.forwardRef<
    React.ElementRef<typeof ToastPrimitive.Root>,
    React.ComponentPropsWithoutRef<typeof ToastPrimitive.Root> & VariantProps<typeof toastVariants>
>(({ className, variant, ...props }, ref) => (
    <ToastPrimitive.Root
        ref={ref}
        className={cn(toastVariants({ variant }), className)}
        {...props}
    />
));
Toast.displayName = ToastPrimitive.Root.displayName;

const ToastTitle = React.forwardRef<
    React.ElementRef<typeof ToastPrimitive.Title>,
    React.ComponentPropsWithoutRef<typeof ToastPrimitive.Title>
>(({ className, ...props }, ref) => (
    <ToastPrimitive.Title
        ref={ref}
        className={cn("text-sm font-semibold", className)}
        {...props}
    />
));
ToastTitle.displayName = ToastPrimitive.Title.displayName;

const ToastDescription = React.forwardRef<
    React.ElementRef<typeof ToastPrimitive.Description>,
    React.ComponentPropsWithoutRef<typeof ToastPrimitive.Description>
>(({ className, ...props }, ref) => (
    <ToastPrimitive.Description
        ref={ref}
        className={cn("text-xs opacity-90", className)}
        {...props}
    />
));
ToastDescription.displayName = ToastPrimitive.Description.displayName;

const ToastClose = React.forwardRef<
    React.ElementRef<typeof ToastPrimitive.Close>,
    React.ComponentPropsWithoutRef<typeof ToastPrimitive.Close>
>(({ className, ...props }, ref) => (
    <ToastPrimitive.Close
        ref={ref}
        className={cn(
            "absolute right-1 top-1 rounded-md p-1 text-foreground/50 opacity-0 transition-opacity hover:text-foreground focus:opacity-100 focus:outline-none focus:ring-1 group-hover:opacity-100",
            className,
        )}
        toast-close=""
        {...props}
    >
        <X className="h-3 w-3" />
    </ToastPrimitive.Close>
));
ToastClose.displayName = ToastPrimitive.Close.displayName;

export {
    ToastProvider,
    ToastViewport,
    Toast,
    ToastTitle,
    ToastDescription,
    ToastClose,
};
